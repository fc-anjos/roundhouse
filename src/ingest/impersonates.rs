//! `impersonates :user` (pretender) → `true_user`, wrapped `current_user`,
//! `impersonate_user`, and `stop_impersonating_user`.
//!
//! Pretender's class-body macro is method synthesis, not a filter.
//! Recognized shape: `impersonates :scope` with no kwargs. When the
//! controller already defines `current_<scope>`, that body is renamed
//! to `true_<scope>` and wrapped. When it does not (Devise may supply
//! `current_<scope>` only as a typed seam), a session-backed
//! `true_<scope>` is synthesized so the pretender surface still exists.
//! Unsupported kwargs leave the call as `Unknown` for the survey.
//! ActionCable `impersonates` is a different host and is not handled here.

use crate::dialect::{Controller, ControllerBodyItem};
use crate::expr::{Expr, ExprNode, Literal};
use crate::ident::Symbol;

struct Impersonation {
    scope: String,
    model: String,
}

pub fn lower_impersonates(app: &mut crate::App) {
    for controller in &mut app.controllers {
        let Some(imp) = take_from_controller_body(controller) else {
            continue;
        };
        let current_name = format!("current_{}", imp.scope);
        let true_name = format!("true_{}", imp.scope);
        let mut renamed = false;
        for item in controller.body.iter_mut() {
            if let ControllerBodyItem::Action { action, .. } = item {
                if action.name.as_str() == current_name {
                    action.name = Symbol::from(true_name.as_str());
                    renamed = true;
                    break;
                }
            }
        }
        let src = method_source(&imp, !renamed);
        let class_src = format!(
            "class {} < ApplicationController\n{}\nend\n",
            controller.name.0.as_str(),
            src
        );
        let (result, diags) = crate::ingest::prism::scope(|| {
            super::controller::ingest_controller(class_src.as_bytes(), "<impersonates>")
        });
        let parsed = match (result, diags.is_empty()) {
            (Ok(Some(c)), true) => c,
            (Ok(None), true) => continue,
            (Ok(_), false) => {
                super::survey::record_synthesis_failure(
                    "<impersonates>",
                    &format!("impersonates forwarder for `{}`", controller.name.0.as_str()),
                    &diags,
                );
                continue;
            }
            (Err(err), _) => {
                super::survey::record(&err);
                continue;
            }
        };
        for item in parsed.body {
            match item {
                ControllerBodyItem::Action { action, .. } => {
                    if renamed && action.name.as_str() == true_name {
                        continue;
                    }
                    if action.name.as_str() == current_name {
                        controller.body.retain(|existing| {
                            !matches!(
                                existing,
                                ControllerBodyItem::Action { action: a, .. }
                                    if a.name.as_str() == current_name
                            )
                        });
                    }
                    controller.body.push(ControllerBodyItem::Action {
                        action,
                        leading_comments: Vec::new(),
                        leading_blank_line: true,
                    });
                }
                ControllerBodyItem::Unknown { expr, .. } => {
                    if is_helper_method_true_user(&expr, &true_name) {
                        controller.body.push(ControllerBodyItem::Unknown {
                            expr,
                            leading_comments: Vec::new(),
                            leading_blank_line: true,
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

fn is_helper_method_true_user(expr: &Expr, true_name: &str) -> bool {
    let ExprNode::Send {
        recv: None,
        method,
        args,
        ..
    } = &*expr.node
    else {
        return false;
    };
    if method.as_str() != "helper_method" {
        return false;
    }
    args.iter().any(|a| {
        matches!(
            &*a.node,
            ExprNode::Lit {
                value: Literal::Sym { value: name }
            } if name.as_str() == true_name
        )
    })
}

fn method_source(imp: &Impersonation, synthesize_true_user: bool) -> String {
    let scope = &imp.scope;
    let model = &imp.model;
    let session_key = format!("impersonated_{scope}_id");
    let mut out = String::new();
    if synthesize_true_user {
        // Pretender aliases an existing `current_<scope>`. Without a
        // local definition (e.g. only a typed Devise seam), synthesize
        // an empty true_<scope> so the wrap and impersonate_* surface
        // still exist — no invented host session key.
        out.push_str(&format!("  def true_{scope}\n  end\n"));
    }
    out.push_str(&format!(
        "  helper_method :true_{scope}\n\
         \n\
           def current_{scope}\n\
             if session[:{session_key}]\n\
               @impersonated_{scope} ||= {model}.find_by(id: session[:{session_key}])\n\
             end\n\
             @impersonated_{scope} || true_{scope}\n\
           end\n\
         \n\
           def impersonate_{scope}(resource)\n\
             raise ArgumentError, \"an unpersisted record cannot be impersonated\" if resource.id.nil?\n\
             @impersonated_{scope} = resource\n\
             session[:{session_key}] = resource.id\n\
           end\n\
         \n\
           def stop_impersonating_{scope}\n\
             session.delete(:{session_key})\n\
             @impersonated_{scope} = nil\n\
           end\n"
    ));
    out
}

fn take_from_controller_body(controller: &mut Controller) -> Option<Impersonation> {
    let mut found: Option<Impersonation> = None;
    let mut remove_at: Option<usize> = None;
    for (i, item) in controller.body.iter().enumerate() {
        let ControllerBodyItem::Unknown { expr, .. } = item else {
            continue;
        };
        if let Some(imp) = impersonation_from_call(expr) {
            found = Some(imp);
            remove_at = Some(i);
            break;
        }
    }
    if let Some(i) = remove_at {
        controller.body.remove(i);
    }
    found
}

fn impersonation_from_call(call: &Expr) -> Option<Impersonation> {
    let ExprNode::Send {
        recv: None,
        method,
        args,
        block: None,
        ..
    } = &*call.node
    else {
        return None;
    };
    if method.as_str() != "impersonates" {
        return None;
    }
    if args.len() != 1 {
        return None;
    }
    let ExprNode::Lit {
        value: Literal::Sym { value: name },
    } = &*args[0].node
    else {
        return None;
    };
    let scope = name.as_str().to_string();
    let model = crate::naming::camelize(&scope);
    Some(Impersonation { scope, model })
}
