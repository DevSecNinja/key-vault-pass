//! `kvp` — the key-vault-pass command-line interface.

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use kvp_core::auth::build_cli_credential;
use kvp_core::config::Settings;
use kvp_core::model::{GeneratePasswordOptions, PasswordEntry};
use kvp_core::password::generate_password;
use kvp_core::{BackingStore, Error, FileSecretStore, KeyVaultStore, VaultRepository};
use secrecy::ExposeSecret;

/// Manage passwords stored in Azure Key Vault using Microsoft Entra ID.
#[derive(Parser)]
#[command(name = "kvp", version, about, long_about = None)]
struct Cli {
    /// Key Vault URL (overrides KVP_VAULT_URL).
    #[arg(long, global = true, env = "KVP_VAULT_URL")]
    vault_url: Option<String>,

    /// Use a local file-backed mock vault instead of Azure (for testing).
    #[arg(long, global = true)]
    mock: bool,

    /// Path to the mock vault file (implies --mock). Defaults to
    /// ./kvp-mock-vault.json. Also settable via KVP_MOCK.
    #[arg(
        long = "mock-file",
        global = true,
        env = "KVP_MOCK",
        value_name = "PATH"
    )]
    mock_file: Option<String>,

    #[command(subcommand)]
    command: Command,
}

/// Resolved connection options shared by commands that touch the vault.
struct Ctx {
    vault_url: Option<String>,
    /// `Some(value)` when the mock store is active (`value` is a path or `"1"`).
    mock: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Create or update a password entry.
    Set(SetArgs),
    /// Retrieve a password entry.
    Get(GetArgs),
    /// List all managed entries.
    List,
    /// Search entries by name substring (case-insensitive).
    Search { query: String },
    /// Delete a password entry.
    Delete(DeleteArgs),
    /// Generate a strong random password and print it.
    Generate(GenerateArgs),
}

#[derive(Args)]
struct SetArgs {
    /// Entry name (letters, digits, dashes).
    name: String,
    #[arg(short, long)]
    username: Option<String>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    notes: Option<String>,
    /// Provide the password inline (otherwise prompted securely).
    #[arg(long)]
    password: Option<String>,
    /// Generate a strong password instead of prompting.
    #[arg(short, long)]
    generate: bool,
    /// Length for a generated password.
    #[arg(long, default_value_t = 20)]
    length: usize,
    /// Fail if the entry already exists.
    #[arg(long)]
    create_only: bool,
}

#[derive(Args)]
struct GetArgs {
    /// Entry name.
    name: String,
    /// Print the password to stdout.
    #[arg(short, long)]
    show: bool,
}

#[derive(Args)]
struct DeleteArgs {
    /// Entry name.
    name: String,
    /// Skip the confirmation prompt.
    #[arg(short, long)]
    yes: bool,
}

#[derive(Args)]
struct GenerateArgs {
    #[arg(short, long, default_value_t = 20)]
    length: usize,
    #[arg(long)]
    no_symbols: bool,
    #[arg(long)]
    no_digits: bool,
    #[arg(long)]
    no_uppercase: bool,
    #[arg(long)]
    no_lowercase: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("KVP_LOG_LEVEL")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    // Mock is active if --mock is passed or a mock file (flag/env KVP_MOCK) is set.
    let mock = if cli.mock || cli.mock_file.is_some() {
        Some(cli.mock_file.unwrap_or_else(|| "1".to_string()))
    } else {
        None
    };
    let ctx = Ctx {
        vault_url: cli.vault_url,
        mock,
    };
    match run(&ctx, cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Build a repository from the resolved options: the local mock when requested,
/// otherwise Azure Key Vault via the credential chain.
fn repository(ctx: &Ctx) -> Result<VaultRepository<BackingStore>, Error> {
    if let Some(mock) = &ctx.mock {
        let store = FileSecretStore::from_env_value(mock);
        return Ok(VaultRepository::new(BackingStore::Mock(store)));
    }
    let mut settings = Settings::from_env();
    if let Some(url) = &ctx.vault_url {
        settings.vault_url = url.clone();
    }
    let vault_url = settings.require_vault_url()?;
    let credential = build_cli_credential()?;
    let store = KeyVaultStore::new(vault_url, credential)?;
    Ok(VaultRepository::new(BackingStore::KeyVault(store)))
}

async fn run(ctx: &Ctx, command: Command) -> Result<(), Error> {
    match command {
        Command::Set(args) => cmd_set(ctx, args).await,
        Command::Get(args) => cmd_get(ctx, args).await,
        Command::List => cmd_list(ctx).await,
        Command::Search { query } => cmd_search(ctx, query).await,
        Command::Delete(args) => cmd_delete(ctx, args).await,
        Command::Generate(args) => cmd_generate(args),
    }
}

async fn cmd_set(ctx: &Ctx, args: SetArgs) -> Result<(), Error> {
    let password = if args.generate {
        let pw = generate_password(&GeneratePasswordOptions {
            length: args.length,
            ..Default::default()
        })?;
        println!("Generated password: {pw}");
        pw
    } else if let Some(pw) = args.password {
        pw
    } else {
        // Prompt so the password never appears in shell history or the process table.
        let pw = rpassword::prompt_password("Password: ")
            .map_err(|e| Error::Configuration(format!("failed to read password: {e}")))?;
        let confirm = rpassword::prompt_password("Confirm password: ")
            .map_err(|e| Error::Configuration(format!("failed to read password: {e}")))?;
        if pw != confirm {
            return Err(Error::Configuration("passwords did not match".into()));
        }
        pw
    };

    let entry = PasswordEntry::new(
        args.name.clone(),
        password,
        args.username,
        args.url,
        args.notes,
    )?;
    repository(ctx)?.set_entry(&entry, args.create_only).await?;
    println!("Saved entry '{}'.", args.name);
    Ok(())
}

async fn cmd_get(ctx: &Ctx, args: GetArgs) -> Result<(), Error> {
    let entry = repository(ctx)?.get_entry(&args.name).await?;
    println!("name:     {}", entry.name);
    if let Some(u) = &entry.username {
        println!("username: {u}");
    }
    if let Some(u) = &entry.url {
        println!("url:      {u}");
    }
    if let Some(n) = &entry.notes {
        println!("notes:    {n}");
    }
    if let Some(updated) = entry.updated_at {
        println!("updated:  {updated}");
    }
    if args.show {
        println!("password: {}", entry.password.expose_secret());
    } else {
        println!("password: (hidden — pass --show to reveal)");
    }
    Ok(())
}

async fn cmd_list(ctx: &Ctx) -> Result<(), Error> {
    let entries = repository(ctx)?.list_entries(None).await?;
    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }
    for summary in entries {
        let updated = summary
            .updated_at
            .map(|d| d.date().to_string())
            .unwrap_or_else(|| "-".into());
        println!("{}\t{}", summary.name, updated);
    }
    Ok(())
}

async fn cmd_search(ctx: &Ctx, query: String) -> Result<(), Error> {
    let entries = repository(ctx)?.list_entries(Some(&query)).await?;
    if entries.is_empty() {
        println!("No matching entries.");
        return Ok(());
    }
    for summary in entries {
        println!("{}", summary.name);
    }
    Ok(())
}

async fn cmd_delete(ctx: &Ctx, args: DeleteArgs) -> Result<(), Error> {
    if !args.yes {
        use std::io::Write as _;
        eprint!("Delete entry '{}'? [y/N] ", args.name);
        std::io::stderr().flush().ok();
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| Error::Configuration(format!("failed to read input: {e}")))?;
        if !matches!(input.trim(), "y" | "Y" | "yes") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }
    repository(ctx)?.delete_entry(&args.name).await?;
    println!("Deleted entry '{}'.", args.name);
    Ok(())
}

fn cmd_generate(args: GenerateArgs) -> Result<(), Error> {
    let pw = generate_password(&GeneratePasswordOptions {
        length: args.length,
        use_symbols: !args.no_symbols,
        use_digits: !args.no_digits,
        use_uppercase: !args.no_uppercase,
        use_lowercase: !args.no_lowercase,
    })?;
    println!("{pw}");
    Ok(())
}
