use rust_embed::Embed;

// At compile time, bake in the frontend/dist directory relative to the workspace root.
// Set FRONTEND_DIST env var at build time to override.
#[derive(Embed)]
#[folder = "$CARGO_MANIFEST_DIR/../frontend/dist/"]
pub struct Assets;
