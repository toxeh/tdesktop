/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_abstract_socket.h"

#include <QtNetwork/QSslSocket>

namespace MTP::details {

class WsSocket final : public AbstractSocket {
public:
	WsSocket(
		not_null<QThread*> thread,
		const bytes::vector &secret,
		const QString &wsPath,
		const QNetworkProxy &proxy,
		bool protocolForFiles);

	void connectToHost(const QString &address, int port) override;
	bool isGoodStartNonce(bytes::const_span nonce) override;
	void timedOut() override;
	bool isConnected() override;
	bool hasBytesAvailable() override;
	int64 read(bytes::span buffer) override;
	void write(bytes::const_span prefix, bytes::const_span buffer) override;

	int32 debugState() override;
	QString debugPostfix() const override;

private:
	enum class State {
		NotConnected,
		Connecting,
		WaitingUpgrade,
		Connected,
		Error,
	};

	void plainConnected();
	void plainDisconnected();
	void plainReadyRead();
	void handleError(int errorCode = 0);
	void sendUpgradeRequest();
	void readUpgradeResponse();
	void readData();
	[[nodiscard]] bool parseWsFrame();

	[[nodiscard]] QByteArray buildWsFrame(
		bytes::const_span payload) const;

	const bytes::vector _secret;
	const QByteArray _wsPath;
	QSslSocket _socket;
	State _state = State::NotConnected;
	QByteArray _incoming;
	QByteArray _payloadBuffer;
	int _payloadReadPos = 0;
	QByteArray _wsKey;

};

} // namespace MTP::details
