use clap::Parser;

#[derive(Parser)]
#[clap(name = "dir_build")]
#[clap(author = "Danny Robers <danny@erebus.cymru>")]
#[clap(version = "1.0")]
#[clap(about = "Builds out my directory structure \
                and folders depending on if I am on a client \
                job or CTF", long_about = None)]
struct Arg {
    #[clap(short, long, value_parser)]
    name: Option<String>,

    #[clap(short, long, value_parser)]
    HTB: Option<String>,

    #[clap(short, long, value_parser)]
    THM: Option<String>,

}

fn main() {

    let args = Arg::parse();


}
