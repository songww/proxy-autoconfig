#[cfg(test)]
mod tests {
    use adblock::filters::network::{NetworkFilter, NetworkMatchable};
    fn rules_inpector(rules: &[NetworkFilter]) {
        let rules: Vec<_> = rules
            .iter()
            .filter(|rule| {
                if rule.opt_domains.is_some() {
                    return true;
                }
                if rule.opt_not_domains.is_some() {
                    return true;
                }
                if rule.modifier_option.is_some() {
                    return true;
                }
                if rule.opt_domains_union.is_some() {
                    return true;
                }
                if rule.opt_not_domains_union.is_some() {
                    return true;
                }
                if rule.is_regex() || rule.is_complete_regex() {
                    println!("{}", rule.get_regex());
                }
                if rule.is_csp() {
                    dbg!("csp", rule);
                }
                if rule.is_redirect() {
                    dbg!("redirect", rule);
                }
                if rule.is_exception() {
                    // dbg!("exception", rule);
                }
                if rule.is_important() {
                    dbg!("important", rule);
                }
                if rule.is_hostname_anchor() {
                    // println!("hostname anchor {rule:?}");
                }
                if rule.is_badfilter() {
                    println!("badfilter {rule:#?}");
                }
                if rule.is_left_anchor() {
                    // println!("left anchor {rule:#?}");
                }
                if rule.is_right_anchor() {
                    println!("right anchor {rule:#?}");
                }
                if rule.is_removeparam() {
                    println!("remove param {rule:?}");
                }
                if rule.is_generic_hide() {
                    println!("generic hide {rule:?}");
                }
                false
            })
            // .take(20)
            .collect();
        dbg!(&rules);
    }
}
