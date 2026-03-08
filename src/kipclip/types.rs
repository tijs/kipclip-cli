use serde::{Deserialize, Serialize};

/// AT Protocol collection names
pub const BOOKMARK_COLLECTION: &str = "community.lexicon.bookmarks.bookmark";
pub const ANNOTATION_COLLECTION: &str = "com.kipclip.annotation";

/// Bookmark record stored on PDS (community.lexicon.bookmarks.bookmark)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BookmarkRecord {
    pub subject: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Annotation sidecar record (com.kipclip.annotation)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnnotationRecord {
    pub subject: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favicon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// URL metadata from enrichment endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub favicon: Option<String>,
    pub image: Option<String>,
}

/// Enriched bookmark combining bookmark + annotation data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrichedBookmark {
    pub uri: String,
    pub cid: String,
    pub rkey: String,
    pub subject: String,
    pub created_at: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub favicon: Option<String>,
    pub image: Option<String>,
    pub note: Option<String>,
}

/// A PDS record as returned by listRecords
#[derive(Debug, Clone)]
pub struct PdsRecord {
    pub uri: String,
    pub cid: String,
    pub value: serde_json::Value,
}

/// Response from com.atproto.repo.createRecord
#[derive(Debug, Clone)]
pub struct CreateRecordResponse {
    pub uri: String,
}

/// Response from com.atproto.repo.getRecord
#[derive(Debug, Clone)]
pub struct GetRecordResponse {
    pub value: serde_json::Value,
}
