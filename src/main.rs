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
    /// Log in with AT Protocol OAuth (default), or explicitly use an app password
    ///
    /// OAuth opens a browser, then asks for the complete callback URL at a hidden prompt.
    /// A connection-refused page at http://127.0.0.1:4000/oauth/callback is expected:
    /// kip starts no callback server. If the browser cannot open, use the printed URL.
    Login {
        /// Your AT Protocol handle (e.g. tijs.org)
        handle: String,
        /// Print the OAuth URL without opening a browser; still paste the hidden callback
        #[arg(long, conflicts_with = "app_password_env")]
        headless: bool,
        /// Read an app password from this process's environment (NAME only, never the value)
        #[arg(long, value_name = "ENV_NAME", conflicts_with = "headless")]
        app_password_env: Option<String>,
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
    /// Fetch page metadata for a URL (read-only, no login required)
    Metadata {
        /// URL to fetch metadata for
        url: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Build a PDS client from the stored session
async fn make_pds_client() -> Result<PdsClient> {
    let info = auth::get_session_info()?;
    let session = auth::restore_session(&info).await?;
    PdsClient::new(session, &info.did)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Login {
            handle,
            headless,
            app_password_env,
        } => commands::login::run(&handle, headless, app_password_env.as_deref()).await,
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
        Commands::Metadata { url, json } => commands::metadata::run(&url, json).await,
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn oauth_help_explains_manual_callback_in_both_browser_modes() {
        let mut cli = Cli::command();
        let help = cli
            .find_subcommand_mut("login")
            .unwrap()
            .render_long_help()
            .to_string();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        for expected in [
            "OAuth opens a browser",
            "complete callback URL at a hidden prompt",
            "connection-refused page at http://127.0.0.1:4000/oauth/callback",
            "kip starts no callback server",
            "If the browser cannot open, use the printed URL",
            "without opening a browser; still paste the hidden callback",
        ] {
            assert!(
                help.contains(expected),
                "missing login guidance: {expected}"
            );
        }
    }

    #[test]
    fn oauth_remains_default_and_headless_remains_oauth() {
        for (args, expected_headless) in [
            (vec!["kip", "login", "tijs.org"], false),
            (vec!["kip", "login", "tijs.org", "--headless"], true),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            match cli.command {
                Commands::Login {
                    handle,
                    headless,
                    app_password_env,
                } => {
                    assert_eq!(handle, "tijs.org");
                    assert_eq!(headless, expected_headless);
                    assert!(app_password_env.is_none());
                }
                _ => panic!("wrong command"),
            }
        }
    }

    #[test]
    fn app_password_requires_explicit_name_and_is_not_a_global_option() {
        for selected in ["BLUESKY_PASSWD", "CUSTOM_LOGIN_SECRET"] {
            let cli =
                Cli::try_parse_from(["kip", "login", "tijs.org", "--app-password-env", selected])
                    .unwrap();
            assert!(
                matches!(cli.command, Commands::Login { headless: false, app_password_env: Some(name), .. } if name == selected)
            );
        }
        for args in [
            vec!["kip", "login", "tijs.org", "--app-password-env"],
            vec![
                "kip",
                "login",
                "tijs.org",
                "--headless",
                "--app-password-env",
                "BLUESKY_PASSWD",
            ],
            vec![
                "kip",
                "metadata",
                "https://article.test",
                "--app-password-env",
                "BLUESKY_PASSWD",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }
}
