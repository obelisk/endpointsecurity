// Allow here to prevent compiler errors from the bindgen structs and functions we can't control
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./eps_bindings.rs");

mod parsers;

extern crate libc;
#[macro_use]
extern crate log;

use crossbeam_channel::Sender;
use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use parsers::*;

use block::*;

// Values
use {
    es_auth_result_t_ES_AUTH_RESULT_ALLOW as ES_AUTH_RESULT_ALLOW,
    es_auth_result_t_ES_AUTH_RESULT_DENY as ES_AUTH_RESULT_DENY,
    es_clear_cache_result_t_ES_CLEAR_CACHE_RESULT_ERR_INTERNAL as ES_CLEAR_CACHE_RESULT_ERR_INTERNAL,
    es_clear_cache_result_t_ES_CLEAR_CACHE_RESULT_ERR_THROTTLE as ES_CLEAR_CACHE_RESULT_ERR_THROTTLE,
    es_clear_cache_result_t_ES_CLEAR_CACHE_RESULT_SUCCESS as ES_CLEAR_CACHE_RESULT_SUCCESS,
    es_new_client_result_t_ES_NEW_CLIENT_RESULT_ERR_INTERNAL as ES_NEW_CLIENT_ERROR_INTERNAL,
    es_new_client_result_t_ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT as ES_NEW_CLIENT_ERROR_INVALID_ARGUMENT,
    es_new_client_result_t_ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED as ES_NEW_CLIENT_ERROR_NOT_ENTITLED,
    es_new_client_result_t_ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED as ES_NEW_CLIENT_ERROR_NOT_PERMITTED,
    es_new_client_result_t_ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED as ES_NEW_CLIENT_ERROR_NOT_PRIVILEGED,
    es_new_client_result_t_ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS as ES_NEW_CLIENT_ERROR_TOO_MANY_CLIENTS,
    es_new_client_result_t_ES_NEW_CLIENT_RESULT_SUCCESS as ES_NEW_CLIENT_SUCCESS,
    es_respond_result_t_ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE as ES_RESPOND_RESULT_ERROR_DUPLICATE_RESPONSE,
    es_respond_result_t_ES_RESPOND_RESULT_ERR_EVENT_TYPE as ES_RESPONSE_RESULT_ERROR_EVENT_TYPE,
    es_respond_result_t_ES_RESPOND_RESULT_ERR_INTERNAL as ES_RESPOND_RESULT_ERROR_INTERNAL,
    es_respond_result_t_ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT as ES_RESPONSE_RESULT_ERROR_INVALID_ARGUMENT,
    es_respond_result_t_ES_RESPOND_RESULT_NOT_FOUND as ES_RESPOND_RESULT_NOT_FOUND,
    es_respond_result_t_ES_RESPOND_RESULT_SUCCESS as ES_RESPOND_RESULT_SUCCESS,
    es_return_t_ES_RETURN_SUCCESS as ES_RETURN_SUCCESS,
};

#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum FileModes {
    Read = 0x00000001,
    Write = 0x00000002,
    NonBlock = 0x00000004,
    Append = 0x00000008,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsFile {
    pub path: String,
    pub path_truncated: bool,
    //    pub stat: stat,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsProcess {
    //pub audit_token: rust_audit_token,
    pub ppid: u32,
    pub original_ppid: u32,
    pub pid: u32,
    pub group_id: u32,
    pub session_id: u32,
    pub codesigning_flags: u32,
    pub is_platform_binary: bool,
    pub is_es_client: bool,
    pub cdhash: String,
    pub signing_id: String,
    pub team_id: String,
    pub executable: EsFile,
    //pub tty: EsFile,
    //pub start_time: timeval,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventExec {
    pub target: EsProcess,
    pub args: Vec<String>,
    // __bindgen_anon_1: es_event_exec_t__bindgen_ty_1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventFork {
    pub child: EsProcess,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventClose {
    pub modified: bool,
    pub target: EsFile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventOpen {
    pub fflag: u32,
    pub file: EsFile,
    // reserved: [u8; 64usize],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventKextload {
    pub identifier: String,
    // reserved: [u8; 64usize],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventKextunload {
    pub identifier: String,
    // reserved: [u8; 64usize],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventSignal {
    pub signal: i32,
    pub target: EsProcess,
    //pub reserved: [u8; 64usize],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventLink {
    pub source: EsFile,
    pub target_dir: EsFile,
    pub target_filename: String,
    //pub reserved: [u8; 64usize],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventUnlink {
    pub target: EsFile,
    pub parent_dir: EsFile,
    //pub reserved: [u8; 64usize],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EsDestinationType {
    ExistingFile = 0,
    NewPath = 1,
    Unknown = 2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsRenameDestinationNewPath {
    pub dir: EsFile,
    pub filename: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsRenameDestination {
    pub existing_file: EsFile,
    pub new_path: EsRenameDestinationNewPath,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventRename {
    pub source: EsFile,
    pub destination_type: EsDestinationType,
    pub destination: EsRenameDestination,
    //pub reserved: [u8; 64usize],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsEventReadDir {
    pub target: EsFile,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EsRespondResult {
    Sucess,
    ErrorInvalidArgument,
    ErrorInternal,
    NotFound,
    ErrorDuplicateResponse,
    ErrorEventType,
    UnknownResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EsNewClientResult {
    Success,
    ErrorInvalidArgument,
    ErrorInternal,
    ErrorNotEntitled,
    ErrorNotPermitted,
    ErrorNotPrivileged,
    ErrorTooManyClients,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClearCacheResult {
    Success,
    ErrorInternal,
    ErrorThrottle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsClientError {
    pub details: String,
    pub error_type: EsNewClientResult,
}

impl fmt::Display for EsClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SupportedEsEvent {
    AuthExec = 0,
    AuthOpen = 1,
    AuthKextload = 2,
    AuthRename = 6,
    AuthSignal = 7,
    AuthUnlink = 8,
    NotifyExec = 9,
    NotifyOpen = 10,
    NotifyFork = 11,
    NotifyClose = 12,
    NotifyKextload = 17,
    NotifyKextunload = 18,
    NotifyLink = 19,
    NotifyRename = 25,
    NotifySignal = 31,
    NotifyUnlink = 32,
    AuthLink = 42,
    AuthReadDir = 67,
    NotifyReadDir = 68,
}

impl fmt::Display for SupportedEsEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EsEvent {
    AuthExec(EsEventExec),
    AuthOpen(EsEventOpen),
    AuthKextload(EsEventKextload),
    /*AuthMmap,
    AuthMprotect,
    AuthMount,*/
    AuthRename(EsEventRename),
    AuthSignal(EsEventSignal),
    AuthUnlink(EsEventUnlink),
    NotifyExec(EsEventExec),
    NotifyOpen(EsEventOpen),
    NotifyFork(EsEventFork),
    NotifyClose(EsEventClose),
    /*NotifyCreate,
    NotifyExchangedata,
    NotifyExit,
    NotifyGetTask,*/
    NotifyKextload(EsEventKextload),
    NotifyKextunload(EsEventKextunload),
    NotifyLink(EsEventLink),
    /*NotifyMmap,
    NotifyMprotect,
    NotifyMount,
    NotifyUnmount,
    NotifyIokitOpen,*/
    NotifyRename(EsEventRename),
    /*NotifySetattrlist,
    NotifySetextattr,
    NotifySetflags,
    NotifySetmode,
    NotifySetowner,*/
    NotifySignal(EsEventSignal),
    NotifyUnlink(EsEventUnlink),
    /*NotifyWrite,
    AuthFileProviderMaterialize,
    NotifyFileProviderMaterialize,
    AuthFileProviderUpdate,
    NotifyFileProviderUpdate,
    AuthReadlink,
    NotifyReadlink,
    AuthTruncate,
    NotifyTruncate,*/
    AuthLink(EsEventLink),
    /*NotifyLookup,
    AuthCreate,
    AuthSetattrlist,
    AuthSetextattr,
    AuthSetflags,
    AuthSetmode,
    AuthSetowner,
    AuthChdir,
    NotifyChdir,
    AuthGetattrlist,
    NotifyGetattrlist,
    NotifyStat,
    NotifyAccess,
    AuthChroot,
    NotifyChroot,
    AuthUtimes,
    NotifyUtimes,
    AuthClone,
    NotifyClone,
    NotifyFcntl,
    AuthGetextattr,
    NotifyGetextattr,
    AuthListextattr,
    NotifyListextattr,*/
    AuthReadDir(EsEventReadDir),
    NotifyReadDir(EsEventReadDir),
    /*AuthDeleteextattr,
    NotifyDeleteextattr,
    AuthFsgetpath,
    NotifyFsgetpath,
    NotifyDup,
    AuthSettime,
    NotifySettime,
    NotifyUipcBind,
    AuthUipcBind,
    NotifyUipcConnect,
    AuthUipcConnect,
    AuthExchangedata,
    AuthSetacl,
    NotifySetacl,
    NotifyPtyGrant,
    NotifyPtyClose,
    AuthProcCheck,
    NotifyProcCheck,
    AuthGetTask,
    AuthSearchfs,
    NotifySearchfs,
    AuthFcntl,
    AuthIokitOpen,
    AuthProcSuspendResume,
    NotifyProcSuspendResume,
    NotifyCsInvalidated,
    NotifyGetTaskName,
    NotifyTrace,
    NotifyRemoteThreadCreate,
    AuthRemount,
    NotifyRemount,
    Last,*/
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EsCacheResult {
    Yes,
    No,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EsActionType {
    Auth,
    Notify,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EsAuthResult {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EsResultType {
    Auth,
    Flags,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct EsEventId {
    pub reserved: [u8; 32usize],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsResultNotifyResult {
    pub flags: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsResult {
    pub result_type: EsResultType,
    pub result: EsResultNotifyResult,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EsAction {
    Auth(EsEventId),
    Notify(EsResult),
}

// This is only needed because EsMessage contains a raw pointer
// to the es_message
unsafe impl Send for EsMessage {}
unsafe impl Sync for EsMessage {}
#[derive(Clone, Debug, Serialize)]
pub struct EsMessage {
    pub version: u32,
    pub time: u64,
    pub mach_time: u64,
    pub deadline: u64,
    pub process: EsProcess,
    pub seq_num: u64,
    pub action: EsAction,
    pub action_type: EsActionType,
    pub event: EsEvent,
    #[serde(skip_serializing)]
    raw_message: *const es_message_t,
}

struct EsClientHidden {
    client: *mut es_client_t,
    active_subscriptions: HashSet<SupportedEsEvent>,
}

// Unfortunately this system is a little over zealous
// because it means we have to lock even to read active subscriptions.
// Optimize this later if it provides too much contention with responding
// to messages.
#[derive(Clone)]
pub struct EsClient {
    client: Arc<Mutex<EsClientHidden>>,
}

// TODO: Codegen these in the future
// TODO: Really. Codegen these in the future along with the protobuf defintions
pub fn raw_event_to_supportedesevent(event_type: u64) -> Option<SupportedEsEvent> {
    Some(match event_type {
        0 => SupportedEsEvent::AuthExec,
        1 => SupportedEsEvent::AuthOpen,
        2 => SupportedEsEvent::AuthKextload,
        6 => SupportedEsEvent::AuthRename,
        7 => SupportedEsEvent::AuthSignal,
        8 => SupportedEsEvent::AuthUnlink,
        9 => SupportedEsEvent::NotifyExec,
        10 => SupportedEsEvent::NotifyOpen,
        11 => SupportedEsEvent::NotifyFork,
        12 => SupportedEsEvent::NotifyClose,
        17 => SupportedEsEvent::NotifyKextload,
        18 => SupportedEsEvent::NotifyKextunload,
        19 => SupportedEsEvent::NotifyLink,
        25 => SupportedEsEvent::NotifyRename,
        31 => SupportedEsEvent::NotifySignal,
        32 => SupportedEsEvent::NotifyUnlink,
        42 => SupportedEsEvent::AuthLink,
        67 => SupportedEsEvent::AuthReadDir,
        68 => SupportedEsEvent::NotifyReadDir,
        _ => return None,
    })
}

// TODO: Really. Codegen these in the future along with the protobuf defintions
pub fn supportedesevent_to_raw_event(event_type: &SupportedEsEvent) -> u32 {
    match event_type {
        SupportedEsEvent::AuthExec => 0,
        SupportedEsEvent::AuthOpen => 1,
        SupportedEsEvent::AuthKextload => 2,
        SupportedEsEvent::AuthRename => 6,
        SupportedEsEvent::AuthSignal => 7,
        SupportedEsEvent::AuthUnlink => 8,
        SupportedEsEvent::NotifyExec => 9,
        SupportedEsEvent::NotifyOpen => 10,
        SupportedEsEvent::NotifyFork => 11,
        SupportedEsEvent::NotifyClose => 12,
        SupportedEsEvent::NotifyKextload => 17,
        SupportedEsEvent::NotifyKextunload => 18,
        SupportedEsEvent::NotifyLink => 19,
        SupportedEsEvent::NotifyRename => 25,
        SupportedEsEvent::NotifySignal => 31,
        SupportedEsEvent::NotifyUnlink => 32,
        SupportedEsEvent::AuthLink => 42,
        SupportedEsEvent::AuthReadDir => 67,
        SupportedEsEvent::NotifyReadDir => 68,
    }
}

fn es_notify_callback(
    _client: *mut es_client_t,
    message: *mut es_message_t,
    tx: Sender<EsMessage>,
) {
    let message = match parse_es_message(message) {
        Err(e) => {
            println!("Could not parse message: {}", e);
            return;
        }
        Ok(x) => x,
    };

    match tx.send(message) {
        Err(e) => println!("Error logging event: {}", e),
        _ => (),
    }
}

pub fn create_es_client(tx: Sender<EsMessage>) -> Result<EsClient, EsClientError> {
    let mut client: *mut es_client_t = std::ptr::null_mut();
    let client_ptr: *mut *mut es_client_t = &mut client;

    let handler = ConcreteBlock::new(
        move |client: *mut es_client_t, message: *mut es_message_t| {
            es_notify_callback(client, message, tx.clone());
        },
    )
    .copy();

    match unsafe { es_new_client(client_ptr, &*handler as *const Block<_, _> as *const std::ffi::c_void) } {
        ES_NEW_CLIENT_SUCCESS => {
            let hidden = EsClientHidden {
                client: client,
                active_subscriptions: HashSet::new(),
            };
            Ok(EsClient {
                client: Arc::new(Mutex::new(hidden)),
            }
        )},
        ES_NEW_CLIENT_ERROR_INVALID_ARGUMENT => Err(EsClientError{
            details: String::from("Something incorrect was passed to es_new_client"),
            error_type: EsNewClientResult::ErrorInvalidArgument,
        }),
        ES_NEW_CLIENT_ERROR_INTERNAL => Err(EsClientError{
            details: String::from("es_new_client experienced an internal error"),
            error_type: EsNewClientResult::ErrorInternal,
        }),
        ES_NEW_CLIENT_ERROR_NOT_ENTITLED => Err(EsClientError{
            details: String::from("This process doesn't have the EndpointSecurity entitlement. (Is the binary signed correctly, is there a provisioning profile installed to allow your program to access EPS?)"),
            error_type: EsNewClientResult::ErrorNotEntitled,
        }),
        ES_NEW_CLIENT_ERROR_NOT_PERMITTED => Err(EsClientError{
            details: String::from("This process is not permitted to use the EndpointSecurity Framework. (Do you have Full Disk Access for your process?)"),
            error_type: EsNewClientResult::ErrorNotPermitted,
        }),
        ES_NEW_CLIENT_ERROR_NOT_PRIVILEGED => Err(EsClientError{
            details: String::from("The process must be running as root to access the EndpointSecurity Framework"),
            error_type: EsNewClientResult::ErrorNotPrivileged,
        }),
        ES_NEW_CLIENT_ERROR_TOO_MANY_CLIENTS => Err(EsClientError{
            details: String::from("There are too many clients connected to EndpointSecurit"),
            error_type: EsNewClientResult::ErrorTooManyClients,
        }),
        _ => Err(EsClientError{
            details: String::from("es_new_client returned an unknown error"),
            error_type: EsNewClientResult::Unknown,
        }),
    }
}

// This might not be true. I'm talking with Apple to figure it out but nothing
// seems to have broken with it yet.
// @obelisk Investigate more
unsafe impl Send for EsClient {}
unsafe impl Sync for EsClient {}

impl EsClient {
    // Clear the cache of decisions. This should be done sparringly as it affects ALL
    // client for the entire system. Doing this too frequently will impact system performace
    pub fn clear_cache(&self) -> Result<(), ClearCacheResult> {
        let client = (*self.client).lock();
        let client = match client {
            Ok(c) => c,
            Err(e) => {
                error!("Could not acquire lock for client: {}", e);
                return Err(ClearCacheResult::ErrorInternal);
            }
        };

        let response = unsafe { es_clear_cache(client.client) };

        match response {
            ES_CLEAR_CACHE_RESULT_SUCCESS => Ok(()),
            ES_CLEAR_CACHE_RESULT_ERR_INTERNAL => Err(ClearCacheResult::ErrorInternal),
            ES_CLEAR_CACHE_RESULT_ERR_THROTTLE => Err(ClearCacheResult::ErrorThrottle),
            _ => {
                error!("Unknown response from es_clear_cache. Perhaps the library needs updating?");
                Err(ClearCacheResult::ErrorInternal)
            }
        }
    }

    // Start receiving callbacks for specified events
    pub fn subscribe_to_events(&self, events: &Vec<SupportedEsEvent>) -> bool {
        if events.len() > 128 {
            println!("Too many events to subscribe to!");
            return false;
        }

        let client = (*self.client).lock();
        let mut client = match client {
            Ok(c) => c,
            Err(_) => return false,
        };

        let events: Vec<&SupportedEsEvent> = events
            .iter()
            .filter(|x| !client.active_subscriptions.contains(x))
            .collect();
        if events.len() == 0 {
            debug!(target: "endpointsecurity-rs", "No new events being subscribed to");
            return true;
        }

        let mut c_events: [u32; 128] = [0; 128];
        let mut i = 0;
        for event in &events {
            c_events[i] = supportedesevent_to_raw_event(&*event);
            i += 1;
        }

        unsafe {
            match es_subscribe(client.client, &c_events as *const u32, events.len() as u32) {
                ES_RETURN_SUCCESS => {
                    for event in events {
                        client.active_subscriptions.insert(*event);
                    }
                    true
                }
                _ => false,
            }
        }
    }

    // Unsubscribe from events and stop receiving callbacks for them
    pub fn unsubscribe_to_events(&self, events: &Vec<SupportedEsEvent>) -> bool {
        if events.len() > 128 {
            println!("Too many events to unsubscribe to!");
            return false;
        }

        let client = (*self.client).lock();
        let mut client = match client {
            Ok(c) => c,
            Err(_) => return false,
        };

        let events: Vec<&SupportedEsEvent> = events
            .iter()
            .filter(|x| client.active_subscriptions.contains(x))
            .collect();
        if events.len() == 0 {
            debug!(target: "endpointsecurity-rs", "Not subscribed to any events request to unsubscribe from");
            return true;
        }

        let mut c_events: [u32; 128] = [0; 128];
        let mut i = 0;
        for event in &events {
            c_events[i] = supportedesevent_to_raw_event(&*event);
            i += 1;
        }

        unsafe {
            match es_unsubscribe(client.client, &c_events as *const u32, events.len() as u32) {
                ES_RETURN_SUCCESS => {
                    for event in events {
                        client.active_subscriptions.remove(event);
                    }
                    true
                }
                _ => false,
            }
        }
    }

    // Set your subscriptions to these regardless of what they were before
    pub fn set_subscriptions_to(&self, events: &Vec<SupportedEsEvent>) -> bool {
        if events.len() > 128 {
            println!("Too many events to unsubscribe to!");
            return false;
        }
        let new_subscriptions: Vec<SupportedEsEvent>;
        let remove_subscriptions: Vec<SupportedEsEvent>;

        {
            let client = (*self.client).lock();
            let client = match client {
                Ok(c) => c,
                Err(_) => return false,
            };

            // Filter out all subscriptions that we already have
            new_subscriptions = events
                .iter()
                .filter(|x| !client.active_subscriptions.contains(x))
                .copied()
                .collect();

            // For all subscriptions we have, keep them in this remove list if they are not in our new list
            remove_subscriptions = client
                .active_subscriptions
                .iter()
                .filter(|x| !events.contains(x))
                .copied()
                .collect();
            if !new_subscriptions.is_empty() {
                info!(target: "endpointsecurity-rs", "Adding subscriptions for: {}",
                    new_subscriptions.iter().fold(String::from(""), |acc, x| acc + &x.to_string() + ", "));
            }

            if !remove_subscriptions.is_empty() {
                info!(target: "endpointsecurity-rs", "Removing subscriptions for: {}",
                    remove_subscriptions.iter().fold(String::from(""), |acc, x| acc + &x.to_string() + ", "));
            }
        }
        self.unsubscribe_to_events(&remove_subscriptions)
            && self.subscribe_to_events(&new_subscriptions)
    }

    pub fn respond_to_flags_event(
        &self,
        message: &EsMessage,
        authorized_flags: u32,
        should_cache: &EsCacheResult,
    ) -> EsRespondResult {
        let cache = match should_cache {
            EsCacheResult::Yes => true,
            EsCacheResult::No => false,
        };

        let client = (*self.client).lock();
        let client = match client {
            Ok(c) => c,
            Err(_) => return EsRespondResult::UnknownResponse, // TODO Fix this
        };

        match unsafe {
            es_respond_flags_result(client.client, message.raw_message, authorized_flags, cache)
        } {
            ES_RESPOND_RESULT_SUCCESS => EsRespondResult::Sucess,
            ES_RESPONSE_RESULT_ERROR_INVALID_ARGUMENT => EsRespondResult::ErrorInvalidArgument,
            ES_RESPOND_RESULT_ERROR_INTERNAL => EsRespondResult::ErrorInternal,
            ES_RESPOND_RESULT_NOT_FOUND => EsRespondResult::NotFound,
            ES_RESPOND_RESULT_ERROR_DUPLICATE_RESPONSE => EsRespondResult::ErrorDuplicateResponse,
            ES_RESPONSE_RESULT_ERROR_EVENT_TYPE => EsRespondResult::ErrorEventType,
            _ => EsRespondResult::UnknownResponse,
        }
    }

    pub fn respond_to_auth_event(
        &self,
        message: &EsMessage,
        response: &EsAuthResult,
        should_cache: &EsCacheResult,
    ) -> EsRespondResult {
        let cache = match should_cache {
            EsCacheResult::Yes => true,
            EsCacheResult::No => false,
        };

        let response = match response {
            EsAuthResult::Allow => ES_AUTH_RESULT_ALLOW,
            EsAuthResult::Deny => ES_AUTH_RESULT_DENY,
        };

        let client = (*self.client).lock();
        let client = match client {
            Ok(c) => c,
            Err(_) => return EsRespondResult::UnknownResponse, // TODO Fix this
        };

        match unsafe { es_respond_auth_result(client.client, message.raw_message, response, cache) }
        {
            ES_RESPOND_RESULT_SUCCESS => EsRespondResult::Sucess,
            ES_RESPONSE_RESULT_ERROR_INVALID_ARGUMENT => EsRespondResult::ErrorInvalidArgument,
            ES_RESPOND_RESULT_ERROR_INTERNAL => EsRespondResult::ErrorInternal,
            ES_RESPOND_RESULT_NOT_FOUND => EsRespondResult::NotFound,
            ES_RESPOND_RESULT_ERROR_DUPLICATE_RESPONSE => EsRespondResult::ErrorDuplicateResponse,
            ES_RESPONSE_RESULT_ERROR_EVENT_TYPE => EsRespondResult::ErrorEventType,
            _ => EsRespondResult::UnknownResponse,
        }
    }
}

impl Drop for EsClient {
    fn drop(&mut self) {
        unsafe {
            let client = (*self.client).lock();
            let mut client = match client {
                Ok(c) => c,
                Err(_) => return (),
            };

            es_delete_client(client.client);
            // Probably unnecessary
            client.active_subscriptions.clear();
        }
    }
}
