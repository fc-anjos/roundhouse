//! `invisible_captcha only: :create` → a `before_action` and the private
//! method that asks `ActionController::InvisibleCaptcha`.
//!
//! The gem (`invisible_captcha` 2.x) expands to a spam-detection
//! `before_action`. Generated here as a real filter + method, the way
//! `rate_limit` is. Recognized options: `only:`, `except:`, `prepend:`.
//! Unsupported kwargs (`honeypot:`, `on_spam:`, …) leave the call as
//! `Unknown` so the survey still names them.

use crate::dialect::{Controller, ControllerBodyItem, Filter, FilterKind};
use crate::expr::{Expr, ExprNode, Literal};
use crate::ident::Symbol;

use super::controller_macro_synth::{append_private_actions, expr_symbol_list};

struct Captcha {
    method: String,
    only: Vec<Symbol>,
    except: Vec<Symbol>,
    prepend: bool,
}

pub fn lower_invisible_captcha(app: &mut crate::App) {
    for controller in &mut app.controllers {
        let captchas = take_from_controller_body(controller);
        if captchas.is_empty() {
            continue;
        }
        let mut methods = String::new();
        for c in &captchas {
            methods.push_str(&method_source(c));
        }
        let _ = append_private_actions(controller, "<invisible_captcha>", &methods);
    }
}

fn method_source(c: &Captcha) -> String {
    format!(
        "  def {}\n    if ActionController::InvisibleCaptcha.spam?(params)\n      head :ok\n    end\n  end\n",
        c.method
    )
}

fn take_from_controller_body(controller: &mut Controller) -> Vec<Captcha> {
    let mut found: Vec<Captcha> = Vec::new();
    for item in controller.body.iter_mut() {
        let ControllerBodyItem::Unknown {
            expr,
            leading_comments,
            leading_blank_line,
        } = item
        else {
            continue;
        };
        let Some(mut captcha) = captcha_from_call(expr) else {
            continue;
        };
        if found.iter().any(|f| f.method == captcha.method) {
            captcha.method = format!("{}_{}", captcha.method, found.len() + 1);
        }
        let f = Filter {
            target_span: crate::span::Span::synthetic(),
            kind: FilterKind::Before,
            target: Symbol::from(captcha.method.as_str()),
            from_concern: None,
            only: captcha.only.clone(),
            except: captcha.except.clone(),
            only_style: Default::default(),
            except_style: Default::default(),
            if_cond: None,
            unless_cond: None,
            if_cond_expr: None,
            unless_cond_expr: None,
            block: None,
            prepend: captcha.prepend,
        };
        *item = ControllerBodyItem::Filter {
            filter: f,
            leading_comments: std::mem::take(leading_comments),
            leading_blank_line: *leading_blank_line,
        };
        found.push(captcha);
    }
    found
}

fn captcha_from_call(call: &Expr) -> Option<Captcha> {
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
    if method.as_str() != "invisible_captcha" {
        return None;
    }
    let mut only = Vec::new();
    let mut except = Vec::new();
    let mut prepend = false;
    if args.is_empty() {
        // Bare `invisible_captcha` — all actions.
    } else {
        let [opts] = args.as_slice() else {
            return None;
        };
        let ExprNode::Hash {
            entries,
            kwargs: true,
        } = &*opts.node
        else {
            return None;
        };
        for (k, v) in entries {
            let ExprNode::Lit {
                value: Literal::Sym { value: key },
            } = &*k.node
            else {
                return None;
            };
            match key.as_str() {
                "only" => only = expr_symbol_list(v)?,
                "except" => except = expr_symbol_list(v)?,
                "prepend" => {
                    let ExprNode::Lit {
                        value: Literal::Bool { value: flag },
                    } = &*v.node
                    else {
                        return None;
                    };
                    prepend = *flag;
                }
                _ => return None,
            }
        }
    }
    Some(Captcha {
        method: "detect_invisible_captcha_spam".into(),
        only,
        except,
        prepend,
    })
}
