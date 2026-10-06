//! Shared re-ingest envelope for class-body macros that expand to
//! private controller methods (+ optional `before_action` filters).
//!
//! `rate_limit` and `invisible_captcha` (and peers) synthesize Ruby,
//! re-ingest it under an isolated prism scope, then append the parsed
//! actions. Keep the parse / survey / PrivateMarker dance here once.

use crate::dialect::{Action, Controller, ControllerBodyItem};
use crate::expr::{Expr, ExprNode, Literal};
use crate::ident::Symbol;

/// Re-ingest `method_bodies` (indented `def … end` source) as private
/// actions on `controller`. `tag` is the synthetic source label
/// (`<rate_limit>`, …) and appears in survey failure messages.
///
/// Returns `false` when synthesis failed or produced nothing (caller
/// should skip further work for this controller).
pub(super) fn append_private_actions(
    controller: &mut Controller,
    tag: &str,
    method_bodies: &str,
) -> bool {
    if method_bodies.is_empty() {
        return false;
    }
    let src = format!(
        "class {} < ApplicationController\n  private\n{}end\n",
        controller.name.0.as_str(),
        method_bodies
    );
    // Isolated prism scope — never the outer app ingest — so a bug in
    // the generated method source can't pin parse errors on an
    // unrelated real file (see `ingest::sources`).
    let (result, diags) = crate::ingest::prism::scope(|| {
        super::controller::ingest_controller(src.as_bytes(), tag)
    });
    let parsed = match (result, diags.is_empty()) {
        (Ok(Some(c)), true) => c,
        (Ok(None), true) => return false,
        (Ok(_), false) => {
            let label = tag.trim_matches(|c| c == '<' || c == '>');
            super::survey::record_synthesis_failure(
                tag,
                &format!("{label} forwarder for `{}`", controller.name.0.as_str()),
                &diags,
            );
            return false;
        }
        (Err(err), _) => {
            super::survey::record(&err);
            return false;
        }
    };
    let has_private_marker = controller
        .body
        .iter()
        .any(|item| matches!(item, ControllerBodyItem::PrivateMarker { .. }));
    if !has_private_marker {
        controller.body.push(ControllerBodyItem::PrivateMarker {
            leading_comments: Vec::new(),
            leading_blank_line: true,
        });
    }
    for item in parsed.body {
        if let ControllerBodyItem::Action { action, .. } = item {
            push_action(controller, action);
        }
    }
    true
}

/// Re-ingest arbitrary method source (not forced under `private`) and
/// return the parsed controller body items. Used by macros that mix
/// renames with synthesized public helpers (`impersonates`).
pub(super) fn reingest_controller_body(
    controller_name: &str,
    tag: &str,
    method_src: &str,
) -> Option<Vec<ControllerBodyItem>> {
    let class_src = format!("class {controller_name} < ApplicationController\n{method_src}\nend\n");
    let (result, diags) = crate::ingest::prism::scope(|| {
        super::controller::ingest_controller(class_src.as_bytes(), tag)
    });
    match (result, diags.is_empty()) {
        (Ok(Some(c)), true) => Some(c.body),
        (Ok(None), true) => None,
        (Ok(_), false) => {
            let label = tag.trim_matches(|c| c == '<' || c == '>');
            super::survey::record_synthesis_failure(
                tag,
                &format!("{label} forwarder for `{controller_name}`"),
                &diags,
            );
            None
        }
        (Err(err), _) => {
            super::survey::record(&err);
            None
        }
    }
}

pub(super) fn push_action(controller: &mut Controller, action: Action) {
    controller.body.push(ControllerBodyItem::Action {
        action,
        leading_comments: Vec::new(),
        leading_blank_line: true,
    });
}

/// `:create` / `[:create, :update]` → the names; anything else → None.
/// Shared by IR-level macro parsers (`rate_limit`, `invisible_captcha`, …).
pub(super) fn expr_symbol_list(v: &Expr) -> Option<Vec<Symbol>> {
    match &*v.node {
        ExprNode::Lit {
            value: Literal::Sym { value },
        } => Some(vec![value.clone()]),
        ExprNode::Array { elements, .. } => elements
            .iter()
            .map(|e| match &*e.node {
                ExprNode::Lit {
                    value: Literal::Sym { value },
                } => Some(value.clone()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}
