import { TOOLS } from '../data/tools';

export interface SearchResult {
    id: string;
    name: string;
    category: string;
    subcategory: string;
    desc: string;
}

export function searchTools(query: string): SearchResult[] {
    if (!query.trim()) return [];

    const lowerQuery = query.toLowerCase().trim();
    const results: SearchResult[] = [];

    TOOLS.forEach((tool) => {
        // Fuzzy search across name, description, category, subcategory
        if (
            tool.name.toLowerCase().includes(lowerQuery) ||
            tool.desc.toLowerCase().includes(lowerQuery) ||
            tool.category.toLowerCase().includes(lowerQuery) ||
            tool.subcategory.toLowerCase().includes(lowerQuery)
        ) {
            results.push({
                id: tool.id,
                name: tool.name,
                category: tool.category,
                subcategory: tool.subcategory,
                desc: tool.desc
            });
        }
    });

    // Limit to top 10 results
    return results.slice(0, 10);
}
