//! `impersonates :user` (pretender) → `true_user`, wrapped `current_user`,
//! `impersonate_user`, and `stop_impersonating_user`.
//!
//! Pretender's class-body macro is method synthesis, not a filter.
//! Recognized shape: `impersonates :scope` with no kwargs **and** a
//! local `current_<scope>` action on the same controller. That body is
//! renamed to `true_<scope>` and wrapped. Without a local definition
//! (inherited Devise helper only), the call stays `Unknown` — synthesizing
//! an empty `true_<scope>` would shadow the inherited method and return
//! nil when not impersonating. A class-level
//! `alias_method :true_<scope>, :current_<scope>` is not used here:
//! `apply_alias_methods` copies bodies after the wrap is already in the
//! method list, which would recurse. Unsupported kwargs leave the call
//! as `Unknown` for the survey. ActionCable `impersonates` is a different
//! host and is not handled here.
//!
//! Mutation is atomic: the macro and any rename stay uncommitted until
//! re-ingest of the synthesized methods succeeds.

use crate::dialect::{Controller, ControllerBodyItem};
use crate::expr::{Expr, ExprNode, Literal};
use crate::ident::Symbol;

use super::controller_macro_synth::{push_action, reingest_controller_body};

struct Impersonation {
    scope: String,
    model: String,
}

pub fn lower_impersonates(app: &mut crate::App) {
    for controller in &mut app.controllers {
        let Some((macro_idx, imp)) = find_impersonation(controller) else {
            continue;
        };
        let current_name = format!("current_{}", imp.scope);
        let true_name = format!("true_{}", imp.scope);
        let has_local = controller.body.iter().any(|item| {
            matches!(
                item,
                ControllerBodyItem::Action { action, .. }
                    if action.name.as_str() == current_name
            )
        });
        // No local current_* → leave Unsupported (do not shadow inherited).
        if !has_local {
            continue;
        }
        let src = method_source(&imp);
        let Some(parsed_body) = reingest_controller_body(
            controller.name.0.as_str(),
            "<impersonates>",
            &src,
        ) else {
            // Leave the macro and existing methods untouched.
            continue;
        };

        // Commit: drop the macro, rename local current_* → true_*, append synth.
        controller.body.remove(macro_idx);
        for item in controller.body.iter_mut() {
            if let ControllerBodyItem::Action { action, .. } = item {
                if action.name.as_str() == current_name {
                    action.name = Symbol::from(true_name.as_str());
                    break;
                }
            }
        }
        for item in parsed_body {
            match item {
                ControllerBodyItem::Action { action, .. } => {
                    push_action(controller, action);
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

fn method_source(imp: &Impersonation) -> String {
    let scope = &imp.scope;
    let model = &imp.model;
    let session_key = format!("impersonated_{scope}_id");
    // After this re-ingest succeeds, the caller renames local
    // `current_<scope>` → `true_<scope>` and appends this wrap. Do not
    // emit `alias_method` here: `apply_alias_methods` would copy the
    // already-wrapped `current_<scope>` body onto `true_<scope>`.
    format!(
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
    )
}

/// Locate a recognized `impersonates` call without mutating the body.
fn find_impersonation(controller: &Controller) -> Option<(usize, Impersonation)> {
    for (i, item) in controller.body.iter().enumerate() {
        let ControllerBodyItem::Unknown { expr, .. } = item else {
            continue;
        };
        if let Some(imp) = impersonation_from_call(expr) {
            return Some((i, imp));
        }
    }
    None
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
