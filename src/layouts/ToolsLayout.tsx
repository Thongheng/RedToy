import { useState, useMemo, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { AlertCircle } from 'lucide-react';
import { TOOLS } from '../data/tools';
import { CATEGORIES, SUBCATEGORIES } from '../data/categories';
import ToolRenderer from '../components/tools/ToolRenderer';
import type { GlobalInputs } from '../types';

interface ToolsLayoutProps {
    globalInputs: GlobalInputs;
    searchQuery: string;
    clearSearch: () => void;
}

export default function ToolsLayout({ globalInputs, searchQuery, clearSearch }: ToolsLayoutProps) {
    const { category, toolId } = useParams();
    const navigate = useNavigate();
    const location = useLocation();

    // Local state for sidebar expansion
    const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set(category ? [category] : ['WEB']));
    const [showNoToolToast, setShowNoToolToast] = useState(false);

    // Tools filtering logic
    const filteredTools = useMemo(() => {
        let tools = [...TOOLS];

        if (searchQuery.trim()) {
            const query = searchQuery.toLowerCase().trim();
            tools = tools.filter(t =>
                t.name.toLowerCase().includes(query) ||
                t.desc.toLowerCase().includes(query) ||
                t.category.toLowerCase().includes(query) ||
                t.subcategory.toLowerCase().includes(query)
            );
        } else if (category && category !== 'all') {
            tools = tools.filter(t => t.category === category);
        }
        return tools;
    }, [searchQuery, category]);

    // Active Tool Logic
    const currentTool = useMemo(() => TOOLS.find(t => t.id === toolId), [toolId]);

    // Derived State for Tool Arguments (Local to this layout/renderer cycle)
    const [toolArgs, setToolArgs] = useState<Record<string, any>>({});

    // Reset/Load default args when tool changes
    useEffect(() => {
        if (currentTool?.args) {
            const defaults: Record<string, any> = {};
            currentTool.args.forEach(arg => defaults[arg.key] = arg.defaultValue);
            setToolArgs(defaults);
        } else {
            setToolArgs({});
        }
    }, [currentTool]);

    // Expand category if navigated to directly
    useEffect(() => {
        if (category && !expandedCategories.has(category)) {
            setExpandedCategories(prev => new Set([...prev, category]));
        }
    }, [category]);

    // Sidebar Handlers
    const toggleCategory = (cat: string) => {
        setExpandedCategories(prev => {
            const next = new Set(prev);
            if (next.has(cat)) next.delete(cat);
            else next.add(cat);
            return next;
        });
    };

    const handleToolSelect = (id: string, cat: string) => {
        navigate(`/tools/${cat}/${id}`);
    };

    const updateArg = (key: string, value: any) => {
        setToolArgs(prev => ({ ...prev, [key]: value }));
    };

    const handleCopy = (text: string) => {
        navigator.clipboard.writeText(text);
        // Toast handled globally or locally if needed
        // For now relying on simple browser behavior or add toast context later
    };

    return (
        <div className="flex h-[calc(100vh-65px)]">
            {/* Sidebar */}
            <aside className="w-64 bg-[#0d1117]/50 border-r border-white/5 overflow-y-auto hidden lg:block">
                <div className="p-4">
                    {searchQuery && (
                        <div className="mb-4 p-3 rounded-lg bg-[#a2ff00]/10 border border-[#a2ff00]/20">
                            <div className="text-xs text-[#a2ff00] font-bold mb-1">Search Results</div>
                            <div className="text-xs text-gray-400">"{searchQuery}" - {filteredTools.length} matches</div>
                            <button onClick={clearSearch} className="text-xs text-gray-500 hover:text-white mt-2 cursor-pointer">Clear search</button>
                        </div>
                    )}
                    <div className="space-y-1">
                        {searchQuery ? (
                            // Search Results View
                            <div className="space-y-0.5">
                                {filteredTools.map(tool => (
                                    <button
                                        key={tool.id}
                                        onClick={() => handleToolSelect(tool.id, tool.category)}
                                        className={`w-full text-left px-3 py-2 rounded text-xs font-medium transition-all cursor-pointer flex items-center justify-between ${currentTool?.id === tool.id
                                            ? 'text-[#a2ff00] bg-[#a2ff00]/10'
                                            : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                                            }`}
                                    >
                                        <span>{tool.name}</span>
                                        <span className="text-[10px] uppercase text-gray-600">{tool.category}</span>
                                    </button>
                                ))}
                            </div>
                        ) : category ? (
                            // Subcategory View for selected category
                            <>
                                {/* Category Header */}
                                <div className="px-3 py-2 text-xs font-bold text-gray-500 uppercase tracking-wider border-b border-white/5 mb-2">
                                    {CATEGORIES[category]?.label || category}
                                </div>

                                {/* Subcategories */}
                                {(SUBCATEGORIES[category] || []).map(sub => {
                                    const subTools = TOOLS.filter(t => t.category === category && t.subcategory === sub);
                                    if (subTools.length === 0) return null;

                                    const isActiveSubcategory = currentTool?.category === category && currentTool?.subcategory === sub;

                                    return (
                                        <button
                                            key={sub}
                                            onClick={() => {
                                                const firstTool = subTools[0];
                                                if (firstTool) {
                                                    navigate(`/tools/${category}/${firstTool.id}`);
                                                }
                                            }}
                                            className={`w-full text-left px-3 py-2.5 rounded-lg text-sm font-medium transition-all cursor-pointer flex items-center justify-between ${isActiveSubcategory
                                                ? 'text-[#a2ff00] bg-[#a2ff00]/10 border border-[#a2ff00]/20'
                                                : 'text-gray-400 hover:text-white hover:bg-white/5 border border-transparent'
                                                }`}
                                        >
                                            <span>{sub}</span>
                                            <span className="text-xs text-gray-600">{subTools.length}</span>
                                        </button>
                                    );
                                })}
                            </>
                        ) : (
                            // No category selected - show prompt
                            <div className="px-3 py-4 text-center text-gray-500 text-sm">
                                Select a category from the top navigation
                            </div>
                        )}
                    </div>
                </div>
            </aside>

            {/* Content Area */}
            <div className="flex-1 flex flex-col overflow-hidden">
                {/* Tool Tabs - Show tools within current subcategory */}
                {currentTool?.subcategory && category && (
                    <div className="border-b border-white/5 bg-[#0d1117]/30 px-6 py-3 flex items-center gap-2 overflow-x-auto">
                        {TOOLS
                            .filter(t => t.category === category && t.subcategory === currentTool.subcategory)
                            .map(tool => (
                                <button
                                    key={tool.id}
                                    onClick={() => handleToolSelect(tool.id, tool.category)}
                                    className={`px-4 py-2 rounded-lg text-xs font-bold whitespace-nowrap transition-all cursor-pointer flex-shrink-0 ${toolId === tool.id
                                        ? 'bg-[#a2ff00] text-[#05080d]'
                                        : 'bg-[#1a1f28] text-gray-400 hover:bg-[#252a35] hover:text-white border border-white/5'
                                        }`}
                                >
                                    {tool.name}
                                </button>
                            ))}
                    </div>
                )}

                {/* Tool Content Renderer */}
                <div className="flex-1 overflow-y-auto p-8">
                    {!currentTool ? (
                        <div className="flex flex-col items-center justify-center h-full text-center">
                            <AlertCircle size={48} className="text-gray-600 mb-4" />
                            <h3 className="text-xl font-bold text-gray-400 mb-2">Select a tool</h3>
                            <p className="text-gray-500 text-sm mb-4">
                                {searchQuery ? 'No tools match your search.' : 'Choose a category and tool from the sidebar or tabs.'}
                            </p>
                        </div>
                    ) : (
                        <ToolRenderer
                            tool={currentTool}
                            inputs={globalInputs}
                            toolArgs={toolArgs}
                            updateArg={updateArg}
                            handleCopy={handleCopy}
                        />
                    )}
                </div>
            </div>

            {/* Toast for no tool found */}
            <div className={`fixed bottom-6 right-6 bg-red-500/90 border border-red-400 px-6 py-3 rounded-lg shadow-lg transition-all duration-300 ${showNoToolToast ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4 pointer-events-none'
                }`}>
                <div className="flex items-center gap-2 text-white">
                    <AlertCircle size={18} />
                    <span className="font-medium">No tools available in this category yet</span>
                </div>
            </div>
        </div>
    );
}
