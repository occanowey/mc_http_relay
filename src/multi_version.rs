use std::convert::{Into, TryFrom};

use mcproto::{error, handshake, packet, role, sio::StdIoConnection, state, uuid::Uuid};

#[derive(Debug)]
pub struct StatusRequest;

#[derive(Debug)]
pub struct StatusResponse {
    pub response: String,
}

#[derive(Debug)]
pub struct PingRequest {
    pub payload: i64,
}

#[derive(Debug)]
pub struct PingResponse {
    pub payload: i64,
}

pub trait StatusState:
    state::ProtocolState
    + state::RoleStatePackets<role::Server>
    + state::NextProtocolState<handshake::HandshakingState>
    + Sized
where
    Self::RecvPacket: packet::PacketFromIdBody,
{
    type StatusRequest: packet::Packet
        + state::RoleStateReadPacket<role::Server, Self>
        + TryFrom<Self::RecvPacket, Error = error::Error>
        + Into<StatusRequest>;

    type StatusResponse: packet::Packet
        + state::RoleStateWritePacket<role::Server, Self>
        + From<StatusResponse>;

    type PingRequest: packet::Packet
        + state::RoleStateReadPacket<role::Server, Self>
        + TryFrom<Self::RecvPacket, Error = error::Error>
        + Into<PingRequest>;

    type PingResponse: packet::Packet
        + state::RoleStateWritePacket<role::Server, Self>
        + From<PingResponse>;
}

#[derive(Debug)]
pub struct LoginStart {
    pub username: String,
    pub uuid: Option<Uuid>,
}

#[derive(Debug)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
}

#[derive(Debug)]
pub struct EncryptionResponse {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
}

#[derive(Debug)]
pub struct Disconnect {
    pub reason: String,
}

pub trait LoginState:
    state::ProtocolState
    + state::RoleStatePackets<role::Server>
    + state::NextProtocolState<handshake::HandshakingState>
    + Sized
where
    Self::RecvPacket: packet::PacketFromIdBody,
{
    type LoginStart: packet::Packet
        + state::RoleStateReadPacket<role::Server, Self>
        + TryFrom<Self::RecvPacket, Error = error::Error>
        + Into<LoginStart>;

    type EncryptionRequest: packet::Packet
        + state::RoleStateWritePacket<role::Server, Self>
        + From<EncryptionRequest>;

    type EncryptionResponse: packet::Packet
        + state::RoleStateReadPacket<role::Server, Self>
        + TryFrom<Self::RecvPacket, Error = error::Error>
        + Into<EncryptionResponse>;

    type Disconnect: packet::Packet
        + state::RoleStateWritePacket<role::Server, Self>
        + From<Disconnect>;
}

pub trait Protocol
where
    <Self::StatusState as state::RoleStatePackets<role::Server>>::RecvPacket:
        packet::PacketFromIdBody,

    <Self::LoginState as state::RoleStatePackets<role::Server>>::RecvPacket:
        packet::PacketFromIdBody,
{
    const VERSION: i32;

    type StatusState: StatusState;
    type LoginState: LoginState;

    fn read_status_request(
        connection: &mut StdIoConnection<role::Server, Self::StatusState>,
    ) -> color_eyre::Result<StatusRequest> {
        let request: <Self::StatusState as StatusState>::StatusRequest =
            connection.expect_next_packet()?;
        Ok(request.into())
    }

    fn write_status_response(
        connection: &mut StdIoConnection<role::Server, Self::StatusState>,
        status_response: StatusResponse,
    ) -> color_eyre::Result<()> {
        connection.write_packet(
            Into::<<Self::StatusState as StatusState>::StatusResponse>::into(status_response),
        )?;
        Ok(())
    }
    fn read_ping_request(
        connection: &mut StdIoConnection<role::Server, Self::StatusState>,
    ) -> color_eyre::Result<PingRequest> {
        let request: <Self::StatusState as StatusState>::PingRequest =
            connection.expect_next_packet()?;
        Ok(request.into())
    }

    fn write_ping_response(
        connection: &mut StdIoConnection<role::Server, Self::StatusState>,
        status_response: PingResponse,
    ) -> color_eyre::Result<()> {
        connection.write_packet(
            Into::<<Self::StatusState as StatusState>::PingResponse>::into(status_response),
        )?;
        Ok(())
    }

    fn read_login_start(
        connection: &mut StdIoConnection<role::Server, Self::LoginState>,
    ) -> color_eyre::Result<LoginStart> {
        let login_start: <Self::LoginState as LoginState>::LoginStart =
            connection.expect_next_packet()?;
        Ok(login_start.into())
    }

    fn write_encryption_request(
        connection: &mut StdIoConnection<role::Server, Self::LoginState>,
        encryption_request: EncryptionRequest,
    ) -> color_eyre::Result<()> {
        connection.write_packet(
            Into::<<Self::LoginState as LoginState>::EncryptionRequest>::into(encryption_request),
        )?;
        Ok(())
    }

    fn read_encryption_response(
        connection: &mut StdIoConnection<role::Server, Self::LoginState>,
    ) -> color_eyre::Result<EncryptionResponse> {
        let request: <Self::LoginState as LoginState>::EncryptionResponse =
            connection.expect_next_packet()?;
        Ok(request.into())
    }

    fn write_disconnect(
        connection: &mut StdIoConnection<role::Server, Self::LoginState>,
        disconnect: Disconnect,
    ) -> color_eyre::Result<()> {
        connection.write_packet(Into::<<Self::LoginState as LoginState>::Disconnect>::into(
            disconnect,
        ))?;
        Ok(())
    }
}
