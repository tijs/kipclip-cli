mod commands;
mod kipclip;

use clap::{Parser, Subcommand};
use miette::Result;

use kipclip::auth;
use kipclip::pds::PdsClient;

#[derive(Parser)]
#[command(name = "kip", about = "kipclip.com CLI – AT Protocol bookmark manager")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Log in with AT Protocol OAuth
    Login {
        /// Your AT Protocol handle (e.g. tijs.org)
        handle: String,
        /// Print an authorization URL and paste its callback URL (for SSH/headless use)
        #[arg(long)]
        headless: bool,
    },
    /// Clear stored session
    Logout,
    /// Show current user (DID, handle)
    Whoami {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a bookmark
    Add {
        /// URL to bookmark
        url: String,
        /// Tags to apply
        #[arg(short = 't', long = "tag")]
        tags: Vec<String>,
    },
    /// List bookmarks (newest first)
    List {
        /// Filter by tag
        #[arg(short = 't', long = "tag")]
        tag: Option<String>,
        /// Max number of bookmarks to show
        #[arg(short = 'n', long)]
        limit: Option<u32>,
        /// Search by title, URL, or description
        #[arg(long)]
        search: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Search bookmarks (alias for: list --search)
    Search {
        /// Search query
        query: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Open bookmark URL in browser
    Open {
        /// Bookmark ref (rkey prefix, min 4 chars)
        #[arg(name = "ref")]
        reference: String,
    },
    /// Delete bookmark + annotation
    Delete {
        /// Bookmark ref (rkey prefix, min 4 chars)
        #[arg(name = "ref")]
        reference: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
    /// Set or clear a note on a bookmark
    Note {
        /// Bookmark ref (rkey prefix, min 4 chars)
        #[arg(name = "ref")]
        reference: String,
        /// Note text (omit to clear)
        text: Option<String>,
    },
    /// Add tags to a bookmark
    Tag {
        /// Bookmark ref (rkey prefix, min 4 chars)
        #[arg(name = "ref")]
        reference: String,
        /// Tags to add
        #[arg(name = "tag", required = true)]
        tags: Vec<String>,
    },
    /// Remove tags from a bookmark
    Untag {
        /// Bookmark ref (rkey prefix, min 4 chars)
        #[arg(name = "ref")]
        reference: String,
        /// Tags to remove
        #[arg(name = "tag", required = true)]
        tags: Vec<String>,
    },
    /// List all tags with counts
    Tags {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Build a PDS client from the stored session
async fn make_pds_client() -> Result<PdsClient> {
    let info = auth::get_session_info()?;
    let session = match auth::restore_session().await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Session expired. Run: kip login {}", info.handle);
            std::process::exit(1);
        }
    };
    PdsClient::new(session, &info.did)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Login { handle, headless } => commands::login::run(&handle, headless).await,
        Commands::Logout => commands::logout::run(),
        Commands::Whoami { json } => commands::whoami::run(json),

        Commands::Add { url, tags } => {
            let pds = make_pds_client().await?;
            commands::add::run(&pds, &url, &tags).await
        }
        Commands::List {
            tag,
            limit,
            search,
            json,
        } => {
            let pds = make_pds_client().await?;
            commands::list::run(&pds, tag.as_deref(), search.as_deref(), limit, json).await
        }
        Commands::Search { query, json } => {
            let pds = make_pds_client().await?;
            commands::search::run(&pds, &query, json).await
        }
        Commands::Open { reference } => {
            let pds = make_pds_client().await?;
            commands::open::run(&pds, &reference).await
        }
        Commands::Delete { reference, force } => {
            let pds = make_pds_client().await?;
            commands::delete::run(&pds, &reference, force).await
        }
        Commands::Note { reference, text } => {
            let pds = make_pds_client().await?;
            commands::note::run(&pds, &reference, text.as_deref()).await
        }
        Commands::Tag { reference, tags } => {
            let pds = make_pds_client().await?;
            commands::tag::run(&pds, &reference, &tags).await
        }
        Commands::Untag { reference, tags } => {
            let pds = make_pds_client().await?;
            commands::untag::run(&pds, &reference, &tags).await
        }
        Commands::Tags { json } => {
            let pds = make_pds_client().await?;
            commands::tags::run(&pds, json).await
        }
    }
}
