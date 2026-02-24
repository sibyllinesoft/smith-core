use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, STORED, TEXT};
use tantivy::{doc, Index, IndexWriter, ReloadPolicy};

use crate::poller::ToolEntry;

pub struct ToolIndex {
    index: Index,
    tools: Vec<ToolEntry>,
    f_name: Field,
    f_description: Field,
    f_server: Field,
    f_tool_idx: Field,
}

impl ToolIndex {
    pub fn empty() -> Self {
        let (schema, f_name, f_description, f_server, f_tool_idx) = Self::schema();
        let index = Index::create_in_ram(schema);
        Self {
            index,
            tools: Vec::new(),
            f_name,
            f_description,
            f_server,
            f_tool_idx,
        }
    }

    pub fn build(tools: Vec<ToolEntry>) -> Self {
        let (schema, f_name, f_description, f_server, f_tool_idx) = Self::schema();
        let index = Index::create_in_ram(schema);

        let mut writer: IndexWriter = index
            .writer(15_000_000)
            .expect("failed to create tantivy index writer");

        for (idx, tool) in tools.iter().enumerate() {
            // Replace underscores/hyphens with spaces so tantivy tokenizes tool names
            let name_text = tool.name.replace(['_', '-'], " ");
            let desc_text = tool.description.as_deref().unwrap_or("");

            writer
                .add_document(doc!(
                    f_name => name_text,
                    f_description => desc_text,
                    f_server => tool.server.as_str(),
                    f_tool_idx => idx as u64,
                ))
                .expect("failed to add document");
        }

        writer.commit().expect("failed to commit tantivy index");

        Self {
            index,
            tools,
            f_name,
            f_description,
            f_server,
            f_tool_idx,
        }
    }

    pub fn search(&self, query: &str, server_filter: Option<&str>, limit: usize) -> Vec<ToolEntry> {
        let reader = self
            .index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .expect("failed to create reader");

        let searcher = reader.searcher();

        // Pre-process query: replace underscores/hyphens with spaces
        let processed_query = query.replace(['_', '-'], " ");

        let mut query_parser = QueryParser::for_index(
            &self.index,
            vec![self.f_name, self.f_description, self.f_server],
        );
        // Boost name field so tool-name matches rank higher
        query_parser.set_field_boost(self.f_name, 3.0);
        query_parser.set_field_boost(self.f_server, 2.0);

        let parsed = match query_parser.parse_query(&processed_query) {
            Ok(q) => q,
            Err(_) => return Vec::new(),
        };

        let top_docs = match searcher.search(&parsed, &TopDocs::with_limit(limit)) {
            Ok(docs) => docs,
            Err(_) => return Vec::new(),
        };

        top_docs
            .into_iter()
            .filter_map(|(_score, doc_addr)| {
                let doc: tantivy::TantivyDocument = searcher.doc(doc_addr).ok()?;
                let idx = doc.get_first(self.f_tool_idx)?.as_u64()? as usize;
                let tool = self.tools.get(idx)?;
                if let Some(srv) = server_filter {
                    if !tool.server.eq_ignore_ascii_case(srv) {
                        return None;
                    }
                }
                Some(tool.clone())
            })
            .collect()
    }

    pub fn list_server(&self, server: &str) -> Vec<ToolEntry> {
        self.tools
            .iter()
            .filter(|t| t.server.eq_ignore_ascii_case(server))
            .cloned()
            .collect()
    }

    fn schema() -> (Schema, Field, Field, Field, Field) {
        let mut builder = Schema::builder();
        let f_name = builder.add_text_field("name", TEXT);
        let f_description = builder.add_text_field("description", TEXT);
        let f_server = builder.add_text_field("server", TEXT);
        let f_tool_idx = builder.add_u64_field("tool_idx", STORED);
        (builder.build(), f_name, f_description, f_server, f_tool_idx)
    }
}
