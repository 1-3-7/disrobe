#[must_use]
pub fn render(file: &syn::File) -> String {
    prettyplease::unparse(file)
}
