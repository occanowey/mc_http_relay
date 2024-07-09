use super::multi_version::Protocol;
use super::multi_version::{
    Disconnect, EncryptionRequest, EncryptionResponse, LoginStart, LoginState,
};
use super::multi_version::{PingRequest, PingResponse, StatusRequest, StatusResponse, StatusState};

macro_rules! impl_protocol {
    (
        $struct: ident ($version: expr),
        $mod: ident,
        $status: ident [$status_request: ident, $status_response: ident, $ping_request: ident, $ping_response: ident $(,)?],
        $login: ident [$login_start: ident, $encryption_request: ident, $encryption_response: ident, $disconnect: ident $(,)?]
        $(,)?
    ) => {
        impl StatusState for mcproto::versions::$mod::states::StatusState {
            type StatusRequest = mcproto::versions::$mod::packets::status::c2s::$status_request;
            type StatusResponse = mcproto::versions::$mod::packets::status::s2c::$status_response;
            type PingRequest = mcproto::versions::$mod::packets::status::c2s::$ping_request;
            type PingResponse = mcproto::versions::$mod::packets::status::s2c::$ping_response;
        }

        impl LoginState for mcproto::versions::$mod::states::LoginState {
            type LoginStart = mcproto::versions::$mod::packets::login::c2s::$login_start;
            type EncryptionRequest =
                mcproto::versions::$mod::packets::login::s2c::$encryption_request;
            type EncryptionResponse =
                mcproto::versions::$mod::packets::login::c2s::$encryption_response;
            type Disconnect = mcproto::versions::$mod::packets::login::s2c::$disconnect;
        }

        pub struct $struct;

        impl Protocol for $struct {
            const VERSION: i32 = $version;

            type StatusState = mcproto::versions::$mod::states::StatusState;
            type LoginState = mcproto::versions::$mod::states::LoginState;
        }
    };
}

macro_rules! impl_protocol_old {
    ($struct: ident ($version: expr), $mod: ident $(,)?) => {
        impl_protocol!(
            $struct($version), $mod,
            StatusState[Request, Response, Ping, Pong],
            LoginState[LoginStart, EncryptionRequest, EncryptionResponse, Disconnect],
        );
    };
}

macro_rules! impl_protocol_new {
    ($struct: ident ($version: expr), $mod: ident $(,)?) => {
        impl_protocol!(
            $struct($version), $mod,
            StatusState[StatusRequest, StatusResponse, PingRequest, PingResponse],
            LoginState[LoginStart, EncryptionRequest, EncryptionResponse, Disconnect],
        );
    };
}

//
// Status Request
// -----------------------------------------------------------------------------------
//

// impl From<mcproto::versions::v3::packets::status::c2s::Request> for StatusRequest {
//     fn from(_: mcproto::versions::v3::packets::status::c2s::Request) -> Self {
//         todo!()
//     }
// }

impl From<mcproto::versions::v4::packets::status::c2s::Request> for StatusRequest {
    fn from(_: mcproto::versions::v4::packets::status::c2s::Request) -> Self {
        Self
    }
}

impl From<mcproto::versions::v759::packets::status::c2s::StatusRequest> for StatusRequest {
    fn from(_: mcproto::versions::v759::packets::status::c2s::StatusRequest) -> Self {
        Self
    }
}

//
// Status Response
// -----------------------------------------------------------------------------------
//

// impl From<StatusResponse> for mcproto::versions::v3::packets::status::s2c::Response {
//     fn from(value: StatusResponse) -> Self {
//         todo!()
//     }
// }

impl From<StatusResponse> for mcproto::versions::v4::packets::status::s2c::Response {
    fn from(value: StatusResponse) -> Self {
        Self {
            response: value.response,
        }
    }
}

impl From<StatusResponse> for mcproto::versions::v759::packets::status::s2c::StatusResponse {
    fn from(value: StatusResponse) -> Self {
        Self {
            response: value.response,
        }
    }
}

//
// Ping Request
// -----------------------------------------------------------------------------------
//

// impl From<mcproto::versions::v3::packets::status::c2s::Ping> for PingRequest {
//     fn from(value: mcproto::versions::v3::packets::status::c2s::Ping) -> Self {
//         todo!()
//     }
// }

impl From<mcproto::versions::v4::packets::status::c2s::Ping> for PingRequest {
    fn from(value: mcproto::versions::v4::packets::status::c2s::Ping) -> Self {
        Self {
            payload: value.payload,
        }
    }
}

impl From<mcproto::versions::v759::packets::status::c2s::PingRequest> for PingRequest {
    fn from(value: mcproto::versions::v759::packets::status::c2s::PingRequest) -> Self {
        Self {
            payload: value.payload,
        }
    }
}

//
// Ping Response
// -----------------------------------------------------------------------------------
//

// impl From<PingResponse> for mcproto::versions::v3::packets::status::s2c::Pong {
//     fn from(value: PingResponse) -> Self {
//         todo!()
//     }
// }

impl From<PingResponse> for mcproto::versions::v4::packets::status::s2c::Pong {
    fn from(value: PingResponse) -> Self {
        Self {
            payload: value.payload,
        }
    }
}

impl From<PingResponse> for mcproto::versions::v759::packets::status::s2c::PingResponse {
    fn from(value: PingResponse) -> Self {
        Self {
            payload: value.payload,
        }
    }
}

//
// Login Start
// -----------------------------------------------------------------------------------
//

// impl From<mcproto::versions::v3::packets::login::c2s::LoginStart> for LoginStart {
//     fn from(value: mcproto::versions::v3::packets::login::c2s::LoginStart) -> Self {
//         todo!()
//     }
// }

impl From<mcproto::versions::v4::packets::login::c2s::LoginStart> for LoginStart {
    fn from(value: mcproto::versions::v4::packets::login::c2s::LoginStart) -> Self {
        Self {
            username: value.username,
            uuid: None,
        }
    }
}

impl From<mcproto::versions::v759::packets::login::c2s::LoginStart> for LoginStart {
    fn from(value: mcproto::versions::v759::packets::login::c2s::LoginStart) -> Self {
        Self {
            username: value.username,
            uuid: None,
        }
    }
}

impl From<mcproto::versions::v761::packets::login::c2s::LoginStart> for LoginStart {
    fn from(value: mcproto::versions::v761::packets::login::c2s::LoginStart) -> Self {
        Self {
            username: value.username,
            uuid: value.uuid,
        }
    }
}

impl From<mcproto::versions::v764::packets::login::c2s::LoginStart> for LoginStart {
    fn from(value: mcproto::versions::v764::packets::login::c2s::LoginStart) -> Self {
        Self {
            username: value.username,
            uuid: Some(value.uuid),
        }
    }
}

//
// Encryption Request
// -----------------------------------------------------------------------------------
//

// impl From<EncryptionRequest> for mcproto::versions::v3::packets::login::s2c::EncryptionRequest {
//     fn from(value: EncryptionRequest) -> Self {
//         todo!()
//     }
// }

impl From<EncryptionRequest> for mcproto::versions::v4::packets::login::s2c::EncryptionRequest {
    fn from(value: EncryptionRequest) -> Self {
        Self {
            server_id: value.server_id,
            public_key: value.public_key,
            verify_token: value.verify_token,
        }
    }
}

impl From<EncryptionRequest> for mcproto::versions::v47::packets::login::s2c::EncryptionRequest {
    fn from(value: EncryptionRequest) -> Self {
        Self {
            server_id: value.server_id,
            public_key: value.public_key,
            verify_token: value.verify_token,
        }
    }
}

impl From<EncryptionRequest> for mcproto::versions::v766::packets::login::s2c::EncryptionRequest {
    fn from(value: EncryptionRequest) -> Self {
        Self {
            server_id: value.server_id,
            public_key: value.public_key,
            verify_token: value.verify_token,
            should_authenticate: true,
        }
    }
}

//
// Encryption Response
// -----------------------------------------------------------------------------------
//

// impl From<mcproto::versions::v3::packets::login::c2s::EncryptionResponse> for EncryptionResponse {
//     fn from(value: mcproto::versions::v3::packets::login::c2s::EncryptionResponse) -> Self {
//         todo!()
//     }
// }

impl From<mcproto::versions::v4::packets::login::c2s::EncryptionResponse> for EncryptionResponse {
    fn from(value: mcproto::versions::v4::packets::login::c2s::EncryptionResponse) -> Self {
        Self {
            shared_secret: value.shared_secret,
            verify_token: value.verify_token,
        }
    }
}

impl From<mcproto::versions::v47::packets::login::c2s::EncryptionResponse> for EncryptionResponse {
    fn from(value: mcproto::versions::v47::packets::login::c2s::EncryptionResponse) -> Self {
        Self {
            shared_secret: value.shared_secret,
            verify_token: value.verify_token,
        }
    }
}

impl From<mcproto::versions::v759::packets::login::c2s::EncryptionResponse> for EncryptionResponse {
    fn from(_value: mcproto::versions::v759::packets::login::c2s::EncryptionResponse) -> Self {
        unimplemented!("v759 encryption response");
    }
}

impl From<mcproto::versions::v761::packets::login::c2s::EncryptionResponse> for EncryptionResponse {
    fn from(value: mcproto::versions::v761::packets::login::c2s::EncryptionResponse) -> Self {
        Self {
            shared_secret: value.shared_secret,
            verify_token: value.verify_token,
        }
    }
}

//
// Disconnect
// -----------------------------------------------------------------------------------
//

// impl From<Disconnect> for mcproto::versions::v3::packets::login::s2c::Disconnect {
//     fn from(value: Disconnect) -> Self {
//         todo!()
//     }
// }

impl From<Disconnect> for mcproto::versions::v4::packets::login::s2c::Disconnect {
    fn from(value: Disconnect) -> Self {
        Self {
            reason: value.reason,
        }
    }
}

// impl_protocol_old!(ProtocolV3(3), v3);
impl_protocol_old!(ProtocolV4(4), v4);
impl_protocol_old!(ProtocolV5(5), v5);
impl_protocol_old!(ProtocolV47(47), v47);
impl_protocol_old!(ProtocolV107(107), v107);
impl_protocol_old!(ProtocolV108(108), v108);
impl_protocol_old!(ProtocolV109(109), v109);
impl_protocol_old!(ProtocolV110(110), v110);
impl_protocol_old!(ProtocolV210(210), v210);
impl_protocol_old!(ProtocolV315(315), v315);
impl_protocol_old!(ProtocolV316(316), v316);
impl_protocol_old!(ProtocolV335(335), v335);
impl_protocol_old!(ProtocolV338(338), v338);
impl_protocol_old!(ProtocolV340(340), v340);
impl_protocol_old!(ProtocolV393(393), v393);
impl_protocol_old!(ProtocolV401(401), v401);
impl_protocol_old!(ProtocolV404(404), v404);
impl_protocol_old!(ProtocolV477(477), v477);
impl_protocol_old!(ProtocolV480(480), v480);
impl_protocol_old!(ProtocolV485(485), v485);
impl_protocol_old!(ProtocolV490(490), v490);
impl_protocol_old!(ProtocolV498(498), v498);
impl_protocol_old!(ProtocolV573(573), v573);
impl_protocol_old!(ProtocolV575(575), v575);
impl_protocol_old!(ProtocolV578(578), v578);
impl_protocol_old!(ProtocolV735(735), v735);
impl_protocol_old!(ProtocolV736(736), v736);
impl_protocol_old!(ProtocolV751(751), v751);
impl_protocol_old!(ProtocolV753(753), v753);
impl_protocol_old!(ProtocolV754(754), v754);
impl_protocol_old!(ProtocolV755(755), v755);
impl_protocol_old!(ProtocolV756(756), v756);
impl_protocol_old!(ProtocolV757(757), v757);
impl_protocol_old!(ProtocolV758(758), v758);
impl_protocol_new!(ProtocolV759(759), v759);
impl_protocol_new!(ProtocolV760(760), v760);
impl_protocol_new!(ProtocolV761(761), v761);
impl_protocol_new!(ProtocolV762(762), v762);
impl_protocol_new!(ProtocolV763(763), v763);
impl_protocol_new!(ProtocolV764(764), v764);
impl_protocol_new!(ProtocolV765(765), v765);
impl_protocol_new!(ProtocolV766(766), v766);
impl_protocol_new!(ProtocolV767(767), v767);
