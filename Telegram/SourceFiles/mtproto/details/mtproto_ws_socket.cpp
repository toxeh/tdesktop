/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/details/mtproto_ws_socket.h"

#include "base/invoke_queued.h"
#include "base/random.h"

#include <QtCore/QtEndian>
#include <QtCore/QCryptographicHash>
#include <QtNetwork/QSslSocket>

namespace MTP::details {
namespace {

constexpr auto kWsVersion = "13";
constexpr auto kWsGuid = "258EAFA5-E914-47DA-95CA-A5AB0DC85B11";

[[nodiscard]] QByteArray GenerateWsKey() {
	auto raw = QByteArray(16, Qt::Uninitialized);
	bytes::set_random(bytes::make_detached_span(raw));
	return raw.toBase64();
}

[[nodiscard]] QByteArray ExpectedWsAccept(const QByteArray &key) {
	const auto combined = key + kWsGuid;
	const auto hash = QCryptographicHash::hash(
		combined,
		QCryptographicHash::Sha1);
	return hash.toBase64();
}

[[nodiscard]] QByteArray BuildMaskingKey() {
	auto key = QByteArray(4, Qt::Uninitialized);
	bytes::set_random(bytes::make_detached_span(key));
	return key;
}

} // namespace

WsSocket::WsSocket(
	not_null<QThread*> thread,
	const bytes::vector &secret,
	const QString &wsPath,
	const QNetworkProxy &proxy,
	bool protocolForFiles)
: AbstractSocket(thread)
, _secret(secret)
, _wsPath(wsPath.toUtf8()) {
	Expects(_secret.size() >= 17);

	_socket.moveToThread(thread);
	_socket.setProxy(proxy);
	if (protocolForFiles) {
		_socket.setSocketOption(
			QAbstractSocket::SendBufferSizeSocketOption,
			kFilesSendBufferSize);
		_socket.setSocketOption(
			QAbstractSocket::ReceiveBufferSizeSocketOption,
			kFilesReceiveBufferSize);
	}
	const auto wrap = [&](auto handler) {
		return [=](auto &&...args) {
			InvokeQueued(this, [=] { handler(args...); });
		};
	};
	using Error = QAbstractSocket::SocketError;
	connect(
		&_socket,
		&QSslSocket::encrypted,
		wrap([=] { plainConnected(); }));
	connect(
		&_socket,
		&QSslSocket::disconnected,
		wrap([=] { plainDisconnected(); }));
	connect(
		&_socket,
		&QSslSocket::readyRead,
		wrap([=] { plainReadyRead(); }));
	connect(
		&_socket,
		&QAbstractSocket::errorOccurred,
		wrap([=](Error e) { handleError(e); }));
	connect(
		&_socket,
		&QSslSocket::sslErrors,
		wrap([=](const QList<QSslError> &errors) {
			for (const auto &e : errors) {
				logError(888, "SSL: " + e.errorString());
			}
			handleError();
		}));
}

void WsSocket::plainConnected() {
	if (_state != State::Connecting) {
		return;
	}
	_state = State::WaitingUpgrade;
	sendUpgradeRequest();
}

void WsSocket::plainDisconnected() {
	_state = State::NotConnected;
	_incoming.clear();
	_payloadBuffer.clear();
	_payloadReadPos = 0;
	_disconnected.fire({});
}

void WsSocket::plainReadyRead() {
	switch (_state) {
	case State::WaitingUpgrade: return readUpgradeResponse();
	case State::Connected: return readData();
	}
}

void WsSocket::handleError(int errorCode) {
	if (_state != State::Connected) {
		_syncTimeRequests.fire({});
	}
	if (errorCode) {
		logError(errorCode, _socket.errorString());
	}
	_state = State::Error;
	_error.fire({});
}

void WsSocket::sendUpgradeRequest() {
	_wsKey = GenerateWsKey();

	const auto host = _socket.peerName().toUtf8();

	auto request = QByteArray();
	request.append("GET ");
	request.append(_wsPath);
	request.append(" HTTP/1.1\r\n");
	request.append("Host: ");
	request.append(host);
	request.append("\r\n");
	request.append("Upgrade: websocket\r\n");
	request.append("Connection: Upgrade\r\n");
	request.append("Sec-WebSocket-Key: ");
	request.append(_wsKey);
	request.append("\r\n");
	request.append("Sec-WebSocket-Version: ");
	request.append(kWsVersion);
	request.append("\r\n");
	request.append("\r\n");

	_socket.write(request);
}

void WsSocket::readUpgradeResponse() {
	_incoming.append(_socket.readAll());

	// Check if we have the full HTTP response (ends with \r\n\r\n).
	const auto endIndex = _incoming.indexOf("\r\n\r\n");
	if (endIndex < 0) {
		return;
	}

	const auto response = QString::fromLatin1(
		_incoming.constData(),
		endIndex);

	// Verify HTTP 101 Switching Protocols.
	if (!response.startsWith("HTTP/1.1 101")) {
		logError(888, "WebSocket upgrade failed: " + response.left(40));
		handleError();
		return;
	}

	// Verify Sec-WebSocket-Accept header.
	const auto expected = ExpectedWsAccept(_wsKey);
	const auto acceptHeader = QStringLiteral("Sec-WebSocket-Accept: ");
	const auto acceptPos = response.indexOf(
		acceptHeader,
		0,
		Qt::CaseInsensitive);
	if (acceptPos < 0) {
		logError(888, "WebSocket upgrade: missing Accept header.");
		handleError();
		return;
	}
	const auto valueStart = acceptPos + acceptHeader.size();
	const auto lineEnd = response.indexOf("\r\n", valueStart);
	const auto acceptValue = response.mid(
		valueStart,
		(lineEnd > 0 ? lineEnd : response.size()) - valueStart).trimmed();
	if (acceptValue.toLatin1() != expected) {
		logError(888, "WebSocket upgrade: bad Accept value.");
		handleError();
		return;
	}

	// Remove the HTTP response from _incoming, keep any trailing data.
	_incoming.remove(0, endIndex + 4);
	_state = State::Connected;
	_connected.fire({});

	// If there's leftover data after the upgrade, process it.
	if (!_incoming.isEmpty()) {
		InvokeQueued(this, [=] { readData(); });
	}
}

void WsSocket::readData() {
	if (!isConnected()) {
		return;
	}
	_incoming.append(_socket.readAll());
	while (parseWsFrame()) {
	}
	if (hasBytesAvailable()) {
		_readyRead.fire({});
	}
}

bool WsSocket::parseWsFrame() {
	// Minimum WS frame: 2 bytes header.
	if (_incoming.size() < 2) {
		return false;
	}

	const auto data = reinterpret_cast<const uchar*>(_incoming.constData());
	const auto byte0 = data[0];
	const auto byte1 = data[1];

	// Server frames should not be masked.
	const auto masked = (byte1 & 0x80) != 0;
	auto payloadLen = uint64(byte1 & 0x7F);
	int headerLen = 2;

	if (payloadLen == 126) {
		if (_incoming.size() < 4) {
			return false;
		}
		payloadLen = qFromBigEndian<uint16>(data + 2);
		headerLen = 4;
	} else if (payloadLen == 127) {
		if (_incoming.size() < 10) {
			return false;
		}
		payloadLen = qFromBigEndian<uint64>(data + 2);
		headerLen = 10;
	}

	if (masked) {
		headerLen += 4;
	}

	const auto totalFrame = headerLen + int(payloadLen);
	if (_incoming.size() < totalFrame) {
		return false;
	}

	const auto opcode = byte0 & 0x0F;

	// Handle close frame.
	if (opcode == 0x08) {
		handleError();
		return false;
	}

	// Handle ping — respond with pong.
	if (opcode == 0x09) {
		auto pong = QByteArray(2, Qt::Uninitialized);
		pong[0] = char(0x8A); // FIN + pong
		pong[1] = char(0x00); // 0 payload
		_socket.write(pong);
		_incoming.remove(0, totalFrame);
		return true;
	}

	// Handle pong — ignore.
	if (opcode == 0x0A) {
		_incoming.remove(0, totalFrame);
		return true;
	}

	// Binary frame (0x02) or continuation (0x00) — extract payload.
	if (opcode == 0x02 || opcode == 0x00) {
		auto payload = _incoming.mid(headerLen, int(payloadLen));
		if (masked) {
			const auto maskKey = data + (headerLen - 4);
			auto p = reinterpret_cast<uchar*>(payload.data());
			for (int i = 0; i < int(payloadLen); ++i) {
				p[i] ^= maskKey[i % 4];
			}
		}
		_payloadBuffer.append(payload);
		_incoming.remove(0, totalFrame);
		return true;
	}

	// Text frame (0x01) or unknown — skip.
	_incoming.remove(0, totalFrame);
	return true;
}

QByteArray WsSocket::buildWsFrame(bytes::const_span payload) const {
	const auto size = payload.size();
	auto frame = QByteArray();

	// FIN + binary opcode.
	frame.append(char(0x82));

	// Masked + payload length.
	if (size < 126) {
		frame.append(char(0x80 | size));
	} else if (size <= 0xFFFF) {
		frame.append(char(0x80 | 126));
		const auto len16 = qToBigEndian(uint16(size));
		frame.append(reinterpret_cast<const char*>(&len16), 2);
	} else {
		frame.append(char(0x80 | 127));
		const auto len64 = qToBigEndian(uint64(size));
		frame.append(reinterpret_cast<const char*>(&len64), 8);
	}

	// Masking key.
	const auto maskKey = BuildMaskingKey();
	frame.append(maskKey);

	// Masked payload.
	const auto payloadStart = frame.size();
	frame.append(
		reinterpret_cast<const char*>(payload.data()),
		size);
	auto p = reinterpret_cast<uchar*>(frame.data() + payloadStart);
	const auto mk = reinterpret_cast<const uchar*>(maskKey.constData());
	for (int i = 0; i < int(size); ++i) {
		p[i] ^= mk[i % 4];
	}

	return frame;
}

void WsSocket::connectToHost(const QString &address, int port) {
	Expects(_state == State::NotConnected);

	_state = State::Connecting;
	_socket.setPeerVerifyMode(QSslSocket::VerifyPeer);
	_socket.connectToHostEncrypted(address, port, address);
}

bool WsSocket::isGoodStartNonce(bytes::const_span nonce) {
	return true;
}

void WsSocket::timedOut() {
	_syncTimeRequests.fire({});
}

bool WsSocket::isConnected() {
	return (_state == State::Connected);
}

bool WsSocket::hasBytesAvailable() {
	return (_payloadBuffer.size() - _payloadReadPos) > 0;
}

int64 WsSocket::read(bytes::span buffer) {
	const auto available = _payloadBuffer.size() - _payloadReadPos;
	if (available <= 0) {
		return 0;
	}
	const auto toRead = std::min(int64(available), int64(buffer.size()));
	bytes::copy(
		buffer,
		bytes::make_span(_payloadBuffer).subspan(_payloadReadPos, toRead));
	_payloadReadPos += toRead;

	// Compact buffer when fully consumed.
	if (_payloadReadPos >= _payloadBuffer.size()) {
		_payloadBuffer.clear();
		_payloadReadPos = 0;
	}
	return toRead;
}

void WsSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (!isConnected()) {
		return;
	}

	if (!prefix.empty()) {
		// Combine prefix and buffer into a single WS frame.
		auto combined = QByteArray();
		combined.append(
			reinterpret_cast<const char*>(prefix.data()),
			prefix.size());
		combined.append(
			reinterpret_cast<const char*>(buffer.data()),
			buffer.size());
		const auto frame = buildWsFrame(bytes::make_span(combined));
		_socket.write(frame);
	} else {
		const auto frame = buildWsFrame(buffer);
		_socket.write(frame);
	}
}

int32 WsSocket::debugState() {
	return _socket.state();
}

QString WsSocket::debugPostfix() const {
	return u"_ws"_q;
}

} // namespace MTP::details
