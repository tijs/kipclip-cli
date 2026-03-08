use miette::Result;

use crate::kipclip::pds::PdsClient;
use crate::kipclip::refs;
use crate::kipclip::types::*;

pub async fn run(pds: &PdsClient, reference: &str, text: Option<&str>) -> Result<()> {
    let bookmarks = pds.fetch_enriched_bookmarks(None).await?;
    let bookmark = refs::resolve_ref(reference, &bookmarks)?;
    let rkey = bookmark.rkey.clone();
    let title = bookmark
        .title
        .as_deref()
        .unwrap_or(&bookmark.subject)
        .to_string();

    // Get or create annotation record
    match pds.get_record(ANNOTATION_COLLECTION, &rkey).await {
        Ok(record) => {
            let mut value = record.value;
            match text {
                Some(t) => value["note"] = serde_json::Value::String(t.to_string()),
                None => {
                    value
                        .as_object_mut()
                        .map(|obj| obj.remove("note"));
                }
            }
            pds.put_record(ANNOTATION_COLLECTION, &rkey, value).await?;
        }
        Err(_) => {
            // No annotation exists, create one
            let annotation = AnnotationRecord {
                subject: bookmark.uri.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                note: text.map(|t| t.to_string()),
                title: None,
                description: None,
                favicon: None,
                image: None,
            };
            pds.create_record(ANNOTATION_COLLECTION, Some(&rkey), &annotation)
                .await?;
        }
    }

    match text {
        Some(t) => println!("Note set on: {title}\n  \"{t}\""),
        None => println!("Note cleared on: {title}"),
    }
    Ok(())
}
