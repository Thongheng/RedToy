import { useState, useEffect, useRef } from 'react';
import { Search, Terminal, ChevronRight } from 'lucide-react';
import { searchTools } from '../services/searchService';
import type { SearchResult } from '../services/searchService';

interface CommandPaletteProps {
    onSelectTool: (toolId: string, category: string) => void;
}

export function CommandPalette({ onSelectTool }: CommandPaletteProps) {
    const [isOpen, setIsOpen] = useState(false);
    const [query, setQuery] = useState('');
    const [selectedIndex, setSelectedIndex] = useState(0);
    const inputRef = useRef<HTMLInputElement>(null);

    // Filter tools based on query
    const filteredTools = searchTools(query);

    // Global keyboard shortcut: Ctrl+K / Cmd+K
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                setIsOpen(prev => !prev);
                setQuery('');
                setSelectedIndex(0);
            }
            if (e.key === 'Escape') {
                setIsOpen(false);
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    // Auto-focus input when modal opens
    useEffect(() => {
        if (isOpen && inputRef.current) {
            inputRef.current.focus();
        }
    }, [isOpen]);

    // Reset selection when query changes
    useEffect(() => {
        setSelectedIndex(0);
    }, [query]);

    const handleSelect = (tool: SearchResult) => {
        onSelectTool(tool.id, tool.category);
        setIsOpen(false);
        setQuery('');
    };

    const handleInputKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            setSelectedIndex(prev => (prev + 1) % filteredTools.length);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setSelectedIndex(prev => (prev - 1 + filteredTools.length) % filteredTools.length);
        } else if (e.key === 'Enter') {
            if (filteredTools.length > 0) {
                handleSelect(filteredTools[selectedIndex]);
            }
        }
    };

    if (!isOpen) return null;

    return (
        <div
            className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-black/70 backdrop-blur-md animate-fade-in"
            onClick={() => setIsOpen(false)}
        >
            <div
                className="w-full max-w-2xl mx-4 bg-[#0d1117] border border-white/20 rounded-2xl shadow-[0_20px_70px_rgba(0,0,0,0.9)] overflow-hidden animate-slide-up"
                onClick={e => e.stopPropagation()}
            >
                {/* Search Input */}
                <div className="p-5 pb-3">
                    <div className="flex items-center gap-3 px-4 py-3 bg-[#1a1f28]/50 border border-white/10 rounded-xl focus-within:bg-[#1a1f28] transition-all duration-200">
                        <Search className="text-[#a2ff00] flex-shrink-0" size={18} />
                        <input
                            ref={inputRef}
                            type="text"
                            value={query}
                            onChange={e => setQuery(e.target.value)}
                            onKeyDown={handleInputKeyDown}
                            placeholder="Search tools..."
                            className="flex-1 bg-transparent text-sm font-normal text-white outline-none focus:outline-none focus:ring-0 focus:border-none focus-visible:outline-none focus-visible:ring-0 placeholder:text-gray-500 border-none ring-0"
                            style={{ outline: 'none', boxShadow: 'none', border: 'none' }}
                            autoFocus
                        />
                        <kbd className="px-2.5 py-1 text-[10px] font-bold tracking-wider text-gray-400 bg-[#0d1117] border border-white/10 rounded flex-shrink-0">
                            ESC
                        </kbd>
                    </div>
                </div>

                {/* Results List */}
                {filteredTools.length > 0 ? (
                    <div className="max-h-[420px] overflow-y-auto px-3 pb-3 space-y-1">
                        {filteredTools.map((tool, index) => (
                            <button
                                key={tool.id}
                                onClick={() => handleSelect(tool)}
                                className={`w-full flex items-center justify-between p-4 rounded-lg transition-all duration-150 group ${index === selectedIndex
                                    ? 'bg-[#a2ff00]/15 border border-[#a2ff00]/30 shadow-[0_0_20px_rgba(162,255,0,0.1)] scale-[1.02]'
                                    : 'bg-transparent hover:bg-white/5 border border-transparent'
                                    }`}
                            >
                                <div className="flex items-center gap-4 flex-1 min-w-0">
                                    <div className={`p-2.5 rounded-lg transition-all duration-150 ${index === selectedIndex
                                        ? 'bg-[#a2ff00] text-black shadow-lg'
                                        : 'bg-white/10 text-gray-400 group-hover:bg-white/15'
                                        }`}>
                                        <Terminal size={18} strokeWidth={2.5} />
                                    </div>
                                    <div className="text-left flex-1 min-w-0">
                                        <div className={`font-bold text-base mb-0.5 truncate transition-colors ${index === selectedIndex ? 'text-white' : 'text-gray-200'
                                            }`}>
                                            {tool.name}
                                        </div>
                                        <div className={`text-xs truncate transition-colors ${index === selectedIndex ? 'text-[#a2ff00]/90' : 'text-gray-500'
                                            }`}>
                                            {tool.category} → {tool.subcategory}
                                        </div>
                                    </div>
                                </div>
                                <ChevronRight
                                    size={18}
                                    className={`flex-shrink-0 transition-all duration-150 ${index === selectedIndex ? 'opacity-100 text-[#a2ff00] translate-x-1' : 'opacity-0 text-gray-600'
                                        }`}
                                />
                            </button>
                        ))}
                    </div>
                ) : query ? (
                    <div className="p-12 text-center">
                        <div className="text-gray-500 font-mono text-sm mb-2">No tools found</div>
                        <div className="text-gray-600 text-xs">Try searching for something else</div>
                    </div>
                ) : (
                    <div className="p-10 text-center">
                        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 mb-3">
                            <Search size={14} className="text-gray-500" />
                            <span className="text-xs font-mono text-gray-500">Type to search</span>
                        </div>
                        <div className="text-gray-600 text-xs">
                            Search across all tools and categories
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
