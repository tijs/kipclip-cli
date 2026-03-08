use jacquard::CowStr;
use jacquard::api::com_atproto::repo::{
    create_record::CreateRecord, delete_record::DeleteRecord, get_record::GetRecord,
    list_records::ListRecords, put_record::PutRecord,
};
use jacquard::common::types::ident::AtIdentifier;
use jacquard::common::types::recordkey::{RecordKey, Rkey};
use jacquard::common::types::value::to_data;
use jacquard::common::xrpc::XrpcClient;
use miette::{Result, miette};
use serde::Serialize;

use crate::kipclip::auth::Session;
use crate::kipclip::refs::rkey_from_uri;
use crate::kipclip::types::*;

/// PDS client wrapping an authenticated jacquard session
pub struct PdsClient {
    session: Session,
    did: jacquard::types::string::Did<'static>,
}

impl PdsClient {
    pub fn new(session: Session, did: &str) -> Result<Self> {
        let did_owned = jacquard::types::string::Did::new_owned(did)
            .map_err(|e| miette!("Invalid DID: {e}"))?;
        Ok(Self {
            session,
            did: did_owned,
        })
    }

    fn parse_nsid(collection: &str) -> Result<jacquard::types::string::Nsid<'_>> {
        jacquard::types::string::Nsid::new(collection).map_err(|e| miette!("Invalid NSID: {e}"))
    }

    /// List all records from a collection (handles pagination)
    pub async fn list_records(
        &self,
        collection: &str,
        limit: Option<i64>,
        reverse: bool,
    ) -> Result<Vec<PdsRecord>> {
        let nsid = Self::parse_nsid(collection)?;

        let mut all_records = Vec::new();
        let mut cursor_val: Option<String> = None;
        let page_limit = limit.unwrap_or(100).min(100);

        loop {
            let mut builder = ListRecords::new()
                .repo(AtIdentifier::Did(self.did.clone()))
                .collection(nsid.clone())
                .limit(page_limit);

            if reverse {
                builder = builder.reverse(true);
            }
            if let Some(ref c) = cursor_val {
                builder = builder.cursor(CowStr::from(c.clone()));
            }

            let request = builder.build();
            let response = self
                .session
                .send(request)
                .await
                .map_err(|e| miette!("PDS listRecords failed: {e}"))?;

            let output = response
                .into_output()
                .map_err(|e| miette!("Failed to parse listRecords response: {e}"))?;

            for record in output.records {
                let value_json =
                    serde_json::to_value(&record.value).unwrap_or(serde_json::Value::Null);
                all_records.push(PdsRecord {
                    uri: record.uri.to_string(),
                    cid: record.cid.to_string(),
                    value: value_json,
                });
            }

            // If we have a specific limit, stop when reached
            if let Some(max) = limit {
                if all_records.len() >= max as usize {
                    all_records.truncate(max as usize);
                    break;
                }
            }

            match output.cursor {
                Some(c) if !c.is_empty() => cursor_val = Some(c.to_string()),
                _ => break,
            }
        }

        Ok(all_records)
    }

    /// Create a record in a collection
    pub async fn create_record<T: Serialize>(
        &self,
        collection: &str,
        rkey: Option<&str>,
        record: &T,
    ) -> Result<CreateRecordResponse> {
        let nsid = Self::parse_nsid(collection)?;
        let data = to_data(record).map_err(|e| miette!("Failed to serialize record: {e}"))?;

        let mut builder = CreateRecord::new()
            .repo(AtIdentifier::Did(self.did.clone()))
            .collection(nsid)
            .record(data);

        if let Some(rkey) = rkey {
            let rk = Rkey::new(rkey).map_err(|e| miette!("Invalid rkey: {e}"))?;
            builder = builder.rkey(RecordKey(rk));
        }

        let request = builder.build();
        let response = self
            .session
            .send(request)
            .await
            .map_err(|e| miette!("PDS createRecord failed: {e}"))?;

        let output = response
            .into_output()
            .map_err(|e| miette!("Failed to parse createRecord response: {e}"))?;

        Ok(CreateRecordResponse {
            uri: output.uri.to_string(),
        })
    }

    /// Get a single record
    pub async fn get_record(&self, collection: &str, rkey: &str) -> Result<GetRecordResponse> {
        let nsid = Self::parse_nsid(collection)?;

        let rk = Rkey::new(rkey).map_err(|e| miette!("Invalid rkey: {e}"))?;
        let request = GetRecord::new()
            .repo(AtIdentifier::Did(self.did.clone()))
            .collection(nsid)
            .rkey(RecordKey(rk))
            .build();

        let response = self
            .session
            .send(request)
            .await
            .map_err(|e| miette!("PDS getRecord failed: {e}"))?;

        let output = response
            .into_output()
            .map_err(|e| miette!("Failed to parse getRecord response: {e}"))?;

        let value_json = serde_json::to_value(&output.value).unwrap_or(serde_json::Value::Null);

        Ok(GetRecordResponse { value: value_json })
    }

    /// Update a record (put)
    pub async fn put_record(
        &self,
        collection: &str,
        rkey: &str,
        record: serde_json::Value,
    ) -> Result<()> {
        let nsid = Self::parse_nsid(collection)?;
        let data = to_data(&record).map_err(|e| miette!("Failed to serialize record: {e}"))?;

        let rk = Rkey::new(rkey).map_err(|e| miette!("Invalid rkey: {e}"))?;
        let request = PutRecord::new()
            .repo(AtIdentifier::Did(self.did.clone()))
            .collection(nsid)
            .rkey(RecordKey(rk))
            .record(data)
            .build();

        let response = self
            .session
            .send(request)
            .await
            .map_err(|e| miette!("PDS putRecord failed: {e}"))?;

        response
            .into_output()
            .map_err(|e| miette!("Failed to parse putRecord response: {e}"))?;

        Ok(())
    }

    /// Delete a record
    pub async fn delete_record(&self, collection: &str, rkey: &str) -> Result<()> {
        let nsid = Self::parse_nsid(collection)?;

        let rk = Rkey::new(rkey).map_err(|e| miette!("Invalid rkey: {e}"))?;
        let request = DeleteRecord::new()
            .repo(AtIdentifier::Did(self.did.clone()))
            .collection(nsid)
            .rkey(RecordKey(rk))
            .build();

        self.session
            .send(request)
            .await
            .map_err(|e| miette!("PDS deleteRecord failed: {e}"))?;

        Ok(())
    }

    /// Fetch bookmarks only (no annotation join). Use when you only need
    /// bookmark data (e.g., duplicate checks, tag counts, ref resolution for
    /// operations that don't display annotation fields).
    pub async fn fetch_bookmarks_only(&self, limit: Option<i64>) -> Result<Vec<EnrichedBookmark>> {
        let bookmarks = self.list_records(BOOKMARK_COLLECTION, limit, true).await?;

        let enriched = bookmarks
            .iter()
            .map(|record| {
                let rkey = rkey_from_uri(&record.uri);
                let bookmark: BookmarkRecord = serde_json::from_value(record.value.clone())
                    .unwrap_or(BookmarkRecord {
                        subject: String::new(),
                        created_at: String::new(),
                        tags: Vec::new(),
                    });

                EnrichedBookmark {
                    uri: record.uri.clone(),
                    cid: record.cid.clone(),
                    rkey,
                    subject: bookmark.subject,
                    created_at: bookmark.created_at,
                    tags: bookmark.tags,
                    title: None,
                    description: None,
                    favicon: None,
                    image: None,
                    note: None,
                }
            })
            .collect();

        Ok(enriched)
    }

    /// Fetch bookmarks joined with annotations
    pub async fn fetch_enriched_bookmarks(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<EnrichedBookmark>> {
        let bookmarks = self.list_records(BOOKMARK_COLLECTION, limit, true).await?;
        let annotations = self.list_records(ANNOTATION_COLLECTION, None, true).await?;

        // Build annotation map keyed by rkey
        let mut annotation_map = std::collections::HashMap::with_capacity(annotations.len());
        for record in &annotations {
            let rkey = rkey_from_uri(&record.uri);
            if let Ok(annotation) = serde_json::from_value::<AnnotationRecord>(record.value.clone())
            {
                annotation_map.insert(rkey, annotation);
            }
        }

        // Join bookmarks with annotations
        let enriched = bookmarks
            .iter()
            .map(|record| {
                let rkey = rkey_from_uri(&record.uri);
                let annotation = annotation_map.get(&rkey);
                let bookmark: BookmarkRecord = serde_json::from_value(record.value.clone())
                    .unwrap_or(BookmarkRecord {
                        subject: String::new(),
                        created_at: String::new(),
                        tags: Vec::new(),
                    });

                EnrichedBookmark {
                    uri: record.uri.clone(),
                    cid: record.cid.clone(),
                    rkey: rkey.clone(),
                    subject: bookmark.subject,
                    created_at: bookmark.created_at,
                    tags: bookmark.tags,
                    title: annotation.and_then(|a| a.title.clone()),
                    description: annotation.and_then(|a| a.description.clone()),
                    favicon: annotation.and_then(|a| a.favicon.clone()),
                    image: annotation.and_then(|a| a.image.clone()),
                    note: annotation.and_then(|a| a.note.clone()),
                }
            })
            .collect();

        Ok(enriched)
    }
}
