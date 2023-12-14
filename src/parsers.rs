use crate::{
    audit_token_t, es_action_type_t_ES_ACTION_TYPE_AUTH as ES_ACTION_TYPE_AUTH,
    es_action_type_t_ES_ACTION_TYPE_NOTIFY as ES_ACTION_TYPE_NOTIFY, es_events_t, es_exec_arg,
    es_exec_arg_count, es_file_t, es_message_t, es_message_t__bindgen_ty_1, es_process_t,
    es_string_token_t, pid_t,
};
use std::ffi::CStr;

// Non Event Structures
use crate::{
    EsAction,
    EsActionType,
    EsDestinationType,
    EsEvent,
    EsEventId, // I know this is inconsistent but I don't have a better name for this struct
    EsFile,
    EsMessage,
    EsProcess,
    EsRenameDestination,
    EsRenameDestinationNewPath,
    EsResult,
    EsResultNotifyResult,
    EsResultType,
    SupportedEsEvent,
};

// Event Structures
use crate::{
    EsEventClose, EsEventExec, EsEventFork, EsEventKextload, EsEventKextunload, EsEventLink,
    EsEventOpen, EsEventReadDir, EsEventRename, EsEventSignal, EsEventUnlink,
};

use crate::raw_event_to_supportedesevent;

extern "C" {
    pub fn audit_token_to_pid(audit_token: audit_token_t) -> pid_t;
}

/// Take in an es_event_t from the EndpointSecurity Framework,
/// and parse it into a safe Rust structure.
fn parse_es_action(
    action: es_message_t__bindgen_ty_1,
    action_type: &EsActionType,
) -> Option<EsAction> {
    Some(match action_type {
        EsActionType::Auth => EsAction::Auth(EsEventId {
            reserved: unsafe { action.auth.reserved },
        }),
        EsActionType::Notify => EsAction::Notify(EsResult {
            result_type: {
                match unsafe { action.notify.result_type } {
                    0 => EsResultType::Auth,
                    1 => EsResultType::Flags,
                    _ => {
                        error!("Result Type is broken");
                        return None; // At time of writing these are the only types
                    }
                }
            },
            result: EsResultNotifyResult {
                flags: unsafe { action.notify.result.flags },
            },
        }),
    })
}

/// Take in an es_event_t from the EndpointSecurity Framework,
/// and parse it into a safe Rust structure.
fn parse_es_event(
    event_type: SupportedEsEvent,
    event: es_events_t,
    action_type: &EsActionType,
) -> EsEvent {
    unsafe {
        match event_type {
            SupportedEsEvent::AuthExec | SupportedEsEvent::NotifyExec => {
                let target = event.exec.target;
                let argc = es_exec_arg_count(&event.exec as *const _);
                let mut argv = vec![];
                argv.reserve(argc as usize);
                let mut x = 0;
                while x < argc {
                    argv.push(parse_es_string_token(es_exec_arg(
                        &event.exec as *const _,
                        x as u32,
                    )));
                    x += 1;
                }

                let event = EsEventExec {
                    target: parse_es_process(&*target),
                    args: argv,
                };

                match action_type {
                    EsActionType::Notify => EsEvent::NotifyExec(event),
                    EsActionType::Auth => EsEvent::AuthExec(event),
                }
            }
            SupportedEsEvent::AuthOpen | SupportedEsEvent::NotifyOpen => {
                let file = event.open;
                let event = EsEventOpen {
                    fflag: file.fflag as u32,
                    file: parse_es_file(file.file),
                };
                match action_type {
                    EsActionType::Notify => EsEvent::NotifyOpen(event),
                    EsActionType::Auth => EsEvent::AuthOpen(event),
                }
            }
            SupportedEsEvent::AuthKextload | SupportedEsEvent::NotifyKextload => {
                let load = event.kextload;
                let event = EsEventKextload {
                    identifier: parse_es_string_token(load.identifier),
                };
                match action_type {
                    EsActionType::Notify => EsEvent::NotifyKextload(event),
                    EsActionType::Auth => EsEvent::AuthKextload(event),
                }
            }
            SupportedEsEvent::AuthSignal | SupportedEsEvent::NotifySignal => {
                let target = event.signal.target;
                let event = EsEventSignal {
                    signal: event.signal.sig,
                    target: parse_es_process(&*target),
                };
                match action_type {
                    EsActionType::Notify => EsEvent::NotifySignal(event),
                    EsActionType::Auth => EsEvent::AuthSignal(event),
                }
            }
            SupportedEsEvent::AuthUnlink | SupportedEsEvent::NotifyUnlink => {
                let target = event.unlink.target;
                let parent_dir = event.unlink.target;
                let event = EsEventUnlink {
                    target: parse_es_file(target),
                    parent_dir: parse_es_file(parent_dir),
                };
                match action_type {
                    EsActionType::Notify => EsEvent::NotifyUnlink(event),
                    EsActionType::Auth => EsEvent::AuthUnlink(event),
                }
            }
            SupportedEsEvent::AuthLink | SupportedEsEvent::NotifyLink => {
                let event = EsEventLink {
                    source: parse_es_file(event.link.source),
                    target_dir: parse_es_file(event.link.target_dir),
                    target_filename: parse_es_string_token(event.link.target_filename),
                };
                match action_type {
                    EsActionType::Notify => EsEvent::NotifyLink(event),
                    EsActionType::Auth => EsEvent::AuthLink(event),
                }
            }
            SupportedEsEvent::AuthRename | SupportedEsEvent::NotifyRename => {
                let event = EsEventRename {
                    source: parse_es_file(event.rename.source),
                    destination_type: match event.rename.destination_type {
                        0 => EsDestinationType::ExistingFile,
                        1 => EsDestinationType::NewPath,
                        _ => EsDestinationType::Unknown,
                    },
                    destination: EsRenameDestination {
                        existing_file: parse_es_file(event.rename.destination.existing_file),
                        new_path: EsRenameDestinationNewPath {
                            dir: parse_es_file(event.rename.destination.new_path.dir),
                            filename: parse_es_string_token(
                                event.rename.destination.new_path.filename,
                            ),
                        },
                    },
                };
                match action_type {
                    EsActionType::Notify => EsEvent::NotifyRename(event),
                    EsActionType::Auth => EsEvent::AuthRename(event),
                }
            }
            SupportedEsEvent::AuthReadDir | SupportedEsEvent::NotifyReadDir => {
                let event = EsEventReadDir {
                    target: parse_es_file(event.readdir.target),
                };
                match action_type {
                    EsActionType::Notify => EsEvent::NotifyReadDir(event),
                    EsActionType::Auth => EsEvent::AuthReadDir(event),
                }
            }
            SupportedEsEvent::NotifyFork => EsEvent::NotifyFork(EsEventFork {
                child: parse_es_process(&*event.fork.child),
            }),
            SupportedEsEvent::NotifyKextunload => EsEvent::NotifyKextunload(EsEventKextunload {
                identifier: parse_es_string_token(event.kextunload.identifier),
            }),
            SupportedEsEvent::NotifyClose => EsEvent::NotifyClose(EsEventClose {
                modified: event.close.modified,
                target: parse_es_file(event.close.target),
            }),
        }
    }
}

/// Take in an es_file_t from the EndpointSecurity Framework,
/// and parse it into a safe Rust structure.
fn parse_es_file(file: *mut es_file_t) -> EsFile {
    let f = unsafe { *file };
    EsFile {
        path: unsafe { CStr::from_ptr(f.path.data).to_str().unwrap().to_owned() },
        path_truncated: { f.path_truncated },
    }
}

/// Take in an es_message_t from the EndpointSecurity Framework,
/// and parse it into a safe Rust structure.
pub fn parse_es_message(message: *mut es_message_t) -> Result<EsMessage, &'static str> {
    let message = unsafe { &*message };
    let process = unsafe { &*(message.process) };
    let action_type = match message.action_type {
        ES_ACTION_TYPE_AUTH => EsActionType::Auth,
        ES_ACTION_TYPE_NOTIFY => EsActionType::Notify,
        _ => return Err("Couldn't parse action_type"), // At time of writing these are the only two ways
    };

    let event = if let Some(event) = raw_event_to_supportedesevent(message.event_type as u64) {
        parse_es_event(event, message.event, &action_type)
    } else {
        error!("Error in this event type: {}", message.event_type as u64);
        return Err("Could not parse this event type");
    };

    Ok(EsMessage {
        version: message.version,
        time: message.time.tv_sec as u64,
        mach_time: message.mach_time,
        deadline: message.deadline,
        process: parse_es_process(process),
        seq_num: message.seq_num,
        action: match parse_es_action(message.action, &action_type) {
            Some(x) => x,
            None => return Err("Couldn't parse the action field"),
        },
        action_type: action_type,
        event: event,
        raw_message: message,
    })
}

/// Take in an es_process_t from the EndpointSecurity Framework,
/// and parse it into a safe Rust structure.
fn parse_es_process(process: &es_process_t) -> EsProcess {
    EsProcess {
        ppid: process.ppid as u32,
        original_ppid: process.original_ppid as u32,
        pid: unsafe { audit_token_to_pid(process.audit_token) as u32 },
        group_id: process.group_id as u32,
        session_id: process.session_id as u32,
        codesigning_flags: process.codesigning_flags as u32,
        is_platform_binary: process.is_platform_binary,
        is_es_client: process.is_es_client,
        cdhash: {
            let mut x = String::new();
            x.reserve(40);
            for byte in &process.cdhash {
                x.push_str(format!("{:02X}", byte).as_str());
            }
            x
        },
        signing_id: parse_es_string_token(process.signing_id),
        team_id: parse_es_string_token(process.team_id),
        executable: parse_es_file(process.executable),
    }
}

/// Take in an es_string_token from the EndpointSecurity Framework,
/// and parse it into a safe Rust structure.
fn parse_es_string_token(string_token: es_string_token_t) -> String {
    match string_token.length {
        x if x <= 0 => String::new(),
        _ => match unsafe { CStr::from_ptr(string_token.data).to_str() } {
            Ok(v) => v.to_owned(),
            Err(e) => {
                error!("String would not parse: {}", e);
                String::new()
            }
        },
    }
}
