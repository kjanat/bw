wit_bindgen::generate!({ world: "probe" });
struct Probe;
#[cfg(feature = "html")]
fn html_text(input: String) -> Result<String, String> {
    use html5ever::{parse_document, tendril::TendrilSink};
    use markup5ever_rcdom::{Handle, NodeData, RcDom};
    fn find(node: &Handle) -> Option<Handle> {
        if let NodeData::Element { name, .. } = &node.data {
            if name.local.as_ref() == "pre" {
                return Some(node.clone());
            }
        }
        node.children.borrow().iter().find_map(find)
    }
    fn text(node: &Handle, out: &mut String) {
        if let NodeData::Text { contents } = &node.data {
            out.push_str(&contents.borrow());
        }
        for child in node.children.borrow().iter() {
            text(child, out);
        }
    }
    let dom = parse_document(RcDom::default(), Default::default()).one(input);
    let pre = find(&dom.document).ok_or_else(|| String::from("missing pre"))?;
    let mut output = String::new();
    text(&pre, &mut output);
    Ok(output)
}
impl Guest for Probe {
    fn extract(html: String) -> Result<String, String> {
        #[cfg(feature = "html")]
        {
            html_text(html)
        }
        #[cfg(not(feature = "html"))]
        {
            let _ = html;
            Err(String::from("disabled"))
        }
    }
    fn domain(host: String) -> Option<String> {
        #[cfg(feature = "domain")]
        {
            psl::domain_str(&host).map(String::from)
        }
        #[cfg(not(feature = "domain"))]
        {
            let _ = host;
            None
        }
    }
}
export!(Probe);
