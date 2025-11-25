
import React, { useState, useEffect, useMemo } from 'react';
import { CATEGORIES, TOOLS, REFERENCES, GUIDES, ENABLE_AI } from './constants';
import { GlobalInputs, Theme, ToolArg } from './types';
import { ThemeToggle } from './components/ThemeToggle';
import { GeminiModal } from './components/GeminiModal';
import { ChevronDown, ChevronRight, Copy, Check, Terminal as TerminalIcon, Search, ExternalLink, BookOpen, Map as MapIcon, Settings as SettingsIcon, Menu, X, Bot } from 'lucide-react';

// Define the explicit order for the sidebar
const CATEGORY_ORDER = ['SERVICE', 'WEB', 'WINDOWS', 'AD', 'OTHER', 'EXPLOIT', 'GUIDE', 'REF'];

const App: React.FC = () => {
    // Default to Dark Mode
    const [theme, setTheme] = useState<Theme>('dark');

    // Navigation State
    // Default to HOME view instead of a specific tool
    const [selectedCategory, setSelectedCategory] = useState<string>('HOME');
    const [selectedSubcategory, setSelectedSubcategory] = useState<string>('');
    const [selectedToolId, setSelectedToolId] = useState<string>('');

    // Default all categories to folded (empty set)
    const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

    // Mobile Menu State
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

    // Inputs State (Global) - With LocalStorage Persistence
    const [inputs, setInputs] = useState<GlobalInputs>(() => {
        const saved = localStorage.getItem('redtoy_inputs');
        return saved ? JSON.parse(saved) : {
            target: '',
            domain: '',
            username: '',
            password: '',
            filepath: ''
        };
    });

    // Save inputs whenever they change
    useEffect(() => {
        localStorage.setItem('redtoy_inputs', JSON.stringify(inputs));
    }, [inputs]);

    // Tool Args State (Dynamic)
    const [toolArgs, setToolArgs] = useState<Record<string, any>>({});

    // Modal State
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [sidebarFilter, setSidebarFilter] = useState('');

    // Toast State
    const [showToast, setShowToast] = useState(false);

    // Handle Theme
    useEffect(() => {
        const savedTheme = localStorage.getItem('theme') as Theme | null;
        if (savedTheme) {
            setTheme(savedTheme);
        }
    }, []);

    useEffect(() => {
        if (theme === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
        localStorage.setItem('theme', theme);
    }, [theme]);

    const toggleTheme = () => {
        setTheme(prev => prev === 'light' ? 'dark' : 'light');
    };

    const toggleCategory = (catKey: string) => {
        const newSet = new Set(expandedCategories);
        if (newSet.has(catKey)) {
            newSet.delete(catKey);
        } else {
            newSet.add(catKey);
        }
        setExpandedCategories(newSet);
    };

    // Group Tools AND References AND Guides for Sidebar
    const navStructure = useMemo<Record<string, Set<string>>>(() => {
        const structure: Record<string, Set<string>> = {};

        // Add Tools
        TOOLS.forEach(tool => {
            if (!structure[tool.category]) {
                structure[tool.category] = new Set();
            }
            structure[tool.category].add(tool.subcategory);
        });

        // Add Guides
        GUIDES.forEach(guide => {
            if (!structure[guide.category]) {
                structure[guide.category] = new Set();
            }
            structure[guide.category].add(guide.subcategory);
        });

        // Add References
        REFERENCES.forEach(ref => {
            if (!structure[ref.category]) {
                structure[ref.category] = new Set();
            }
            structure[ref.category].add(ref.subcategory);
        });

        return structure;
    }, []);

    // Filtered Structure based on Search
    const filteredNav = useMemo(() => {
        const result: Record<string, string[]> = {};
        const lowerFilter = sidebarFilter.toLowerCase().trim();

        Object.entries(navStructure).forEach(([catKey, subSet]) => {
            const catDef = CATEGORIES[catKey];
            if (!catDef) return;

            const allSubs = Array.from(subSet as Set<string>);

            if (!lowerFilter) {
                result[catKey] = allSubs;
                return;
            }

            // 1. Check if Category Label matches
            if (catDef.label.toLowerCase().includes(lowerFilter)) {
                result[catKey] = allSubs;
                return;
            }

            // 2. Check Subcategories OR Tools/Refs/Guides inside them
            const matchingSubs = allSubs.filter(sub => {
                // Does subcategory name match?
                if (sub.toLowerCase().includes(lowerFilter)) return true;

                // Do any tools inside this subcategory match?
                const toolsInSub = TOOLS.filter(t => t.category === catKey && t.subcategory === sub);
                const toolMatch = toolsInSub.some(t =>
                    t.name.toLowerCase().includes(lowerFilter) ||
                    t.id.toLowerCase().includes(lowerFilter)
                );
                if (toolMatch) return true;

                // Do any references inside this subcategory match?
                const refsInSub = REFERENCES.filter(r => r.category === catKey && r.subcategory === sub);
                const refMatch = refsInSub.some(r =>
                    r.name.toLowerCase().includes(lowerFilter) ||
                    r.id.toLowerCase().includes(lowerFilter)
                );
                if (refMatch) return true;

                // Do any guides inside this subcategory match?
                const guidesInSub = GUIDES.filter(g => g.category === catKey && g.subcategory === sub);
                const guideMatch = guidesInSub.some(g =>
                    g.name.toLowerCase().includes(lowerFilter) ||
                    g.id.toLowerCase().includes(lowerFilter)
                );
                return guideMatch;
            });

            if (matchingSubs.length > 0) {
                result[catKey] = matchingSubs;
            }
        });
        return result;
    }, [sidebarFilter, navStructure]);


    // Auto-select first tool/guide when subcategory changes (ONLY for non-reference categories)
    useEffect(() => {
        if (selectedCategory === 'HOME') return;
        if (selectedCategory === 'REF') return;

        if (selectedCategory === 'GUIDE') {
            const guidesInSub = GUIDES.filter(g => g.category === selectedCategory && g.subcategory === selectedSubcategory);
            if (guidesInSub.length > 0) {
                const validGuide = guidesInSub.some(g => g.id === selectedToolId);
                if (!validGuide) {
                    setSelectedToolId(guidesInSub[0].id);
                }
            }
            return;
        }

        const toolsInSub = TOOLS.filter(t => t.category === selectedCategory && t.subcategory === selectedSubcategory);
        if (toolsInSub.length > 0) {
            const validTool = toolsInSub.some(t => t.id === selectedToolId);
            if (!validTool) {
                setSelectedToolId(toolsInSub[0].id);
            }
        }
    }, [selectedSubcategory, selectedCategory]);

    // Reset copy state when tool or options change
    const currentTool = TOOLS.find(t => t.id === selectedToolId) || TOOLS[0];
    const currentGuide = GUIDES.find(g => g.id === selectedToolId);

    // Load default args when tool changes
    useEffect(() => {
        if (currentTool && currentTool.args) {
            const defaults: Record<string, any> = {};
            currentTool.args.forEach(arg => {
                defaults[arg.key] = arg.defaultValue;
            });
            setToolArgs(defaults);
        } else {
            setToolArgs({});
        }
    }, [selectedToolId]);

    const generatedCommand = currentTool ? currentTool.generate(inputs, toolArgs) : '';

    const handleCopy = (text: string) => {
        navigator.clipboard.writeText(text);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 2000);
    };

    const handleAskAI = () => {
        setIsModalOpen(true);
    };

    // Sidebar navigation handler
    const handleSubnavClick = (catKey: string, sub: string) => {
        setSelectedCategory(catKey);
        setSelectedSubcategory(sub);
        setIsMobileMenuOpen(false); // Close mobile menu on selection
    };

    const handleLogoClick = () => {
        setSelectedCategory('HOME');
        setSelectedSubcategory('');
        setSelectedToolId('');
    };

    // Determine Config Panel Visibility
    const hasConfiguration = useMemo(() => {
        if (!currentTool) return false;
        return (currentTool.args && currentTool.args.length > 0);
    }, [currentTool]);

    // Determine View Mode
    const isHomeView = selectedCategory === 'HOME';
    const isReferenceView = selectedCategory === 'REF';
    const isGuideView = selectedCategory === 'GUIDE';

    const activeReferences = isReferenceView
        ? REFERENCES.filter(r => r.category === selectedCategory && r.subcategory === selectedSubcategory)
        : [];

    const updateArg = (key: string, value: any) => {
        setToolArgs(prev => ({
            ...prev,
            [key]: value
        }));
    };

    return (
        <div className={`h-screen flex flex-col overflow-hidden bg-toy-bg dark:bg-toy-darkBg text-black dark:text-white transition-colors duration-300 font-sans`}>

            {/* Top Navigation / Inputs */}
            <header className="h-auto border-b-4 border-black bg-white dark:bg-[#1e1e1e] p-3 lg:p-4 flex flex-col gap-3 shadow-hard z-20">
                <div className="flex items-center justify-between">
                    <button onClick={handleLogoClick} className="flex items-center gap-2 min-w-[200px] group">
                        <div className="w-8 h-8 bg-toy-red border-2 border-black rounded flex items-center justify-center text-white font-black shadow-hard-sm group-hover:rotate-12 transition-transform">R</div>
                        <h1 className="font-black text-xl tracking-tighter group-hover:text-toy-red transition-colors">RedToy</h1>
                    </button>

                    {/* Right Side Actions */}
                    <div className="flex items-center gap-3">
                        {/* AI Button - Only visible if enabled */}
                        {ENABLE_AI && (
                            <button
                                onClick={handleAskAI}
                                className="flex items-center gap-2 px-3 py-1.5 bg-black text-white font-bold text-xs rounded border-2 border-black shadow-hard-sm hover:bg-toy-red hover:shadow-none active:translate-y-1 transition-all"
                            >
                                <Bot size={16} />
                                <span className="hidden md:inline">RedTeam AI</span>
                            </button>
                        )}

                        {/* Mobile Hamburger */}
                        <button onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} className="lg:hidden p-2 border-2 border-black rounded bg-gray-100 dark:bg-gray-800">
                            {isMobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
                        </button>
                    </div>
                </div>

                {/* Global Inputs - Wrap in responsive grid */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-2 w-full">
                    {[
                        { label: 'TARGET', key: 'target', placeholder: '10.10.10.5' },
                        { label: 'DOMAIN', key: 'domain', placeholder: 'corp.local' },
                        { label: 'USER', key: 'username', placeholder: 'admin' },
                        { label: 'PASS', key: 'password', placeholder: 'pass123' },
                        { label: 'FILE', key: 'filepath', placeholder: '/path/to/file' },
                    ].map((field) => (
                        <div key={field.key} className="flex flex-col">
                            <label className="text-[9px] lg:text-[10px] font-bold uppercase text-gray-500 dark:text-gray-400 mb-0.5 tracking-wider">{field.label}</label>
                            <input
                                type="text"
                                value={(inputs as any)[field.key]}
                                onChange={e => setInputs({ ...inputs, [field.key]: e.target.value })}
                                placeholder={field.placeholder}
                                className="bg-gray-100 dark:bg-[#2d2d2d] border-2 border-black/20 dark:border-white/10 rounded px-2 py-1.5 text-xs lg:text-sm font-mono focus:outline-none focus:border-toy-red focus:ring-1 focus:ring-toy-red transition-all"
                            />
                        </div>
                    ))}
                </div>
            </header>

            <div className="flex flex-1 overflow-hidden relative">
                {/* Mobile Menu Overlay */}
                {isMobileMenuOpen && (
                    <div className="fixed inset-0 bg-black/50 z-20 lg:hidden" onClick={() => setIsMobileMenuOpen(false)}></div>
                )}

                {/* Sidebar */}
                <aside className={`
            absolute lg:static top-0 left-0 bottom-0 w-64 lg:w-72 
            bg-[#0f172a] text-gray-400 flex flex-col border-r-4 border-black 
            z-30 transform transition-transform duration-300
            ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}>
                    {/* Search Filter */}
                    <div className="p-4 border-b border-gray-800">
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                            <input
                                type="text"
                                value={sidebarFilter}
                                onChange={(e) => setSidebarFilter(e.target.value)}
                                placeholder="Filter tools..."
                                className="w-full bg-[#1e293b] border border-gray-700 rounded pl-9 pr-3 py-2 text-sm focus:outline-none focus:border-toy-red focus:ring-1 focus:ring-toy-red transition-all text-gray-200"
                            />
                        </div>
                    </div>

                    {/* Navigation Tree */}
                    <nav className="flex-1 overflow-y-auto py-2 custom-scrollbar">
                        {Object.keys(filteredNav).length === 0 && (
                            <div className="p-4 text-center text-gray-600 text-sm">No tools found.</div>
                        )}
                        {Object.keys(filteredNav)
                            .sort((a, b) => {
                                // Sort logic: Use index from CATEGORY_ORDER. If not found, put at the end.
                                const idxA = CATEGORY_ORDER.indexOf(a);
                                const idxB = CATEGORY_ORDER.indexOf(b);
                                const valA = idxA === -1 ? 999 : idxA;
                                const valB = idxB === -1 ? 999 : idxB;
                                return valA - valB;
                            })
                            .map((key) => {
                                const cat = CATEGORIES[key];
                                const subcategories = filteredNav[key];

                                const isExpanded = expandedCategories.has(key) || sidebarFilter !== '';
                                const Icon = cat.icon;

                                return (
                                    <div key={key} className="mb-1">
                                        <button
                                            onClick={() => toggleCategory(key)}
                                            className={`w-full flex items-center gap-3 px-4 py-3 text-sm font-bold uppercase tracking-wide hover:text-white transition-colors ${isExpanded ? 'text-white' : 'text-gray-400'}`}
                                        >
                                            <Icon size={18} />
                                            <span className="flex-1 text-left">{cat.label}</span>
                                            {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                                        </button>

                                        {isExpanded && (
                                            <div className="flex flex-col">
                                                {subcategories.map(sub => {
                                                    const isActive = selectedCategory === key && selectedSubcategory === sub;
                                                    return (
                                                        <button
                                                            key={sub}
                                                            onClick={() => handleSubnavClick(key, sub)}
                                                            className={`relative flex items-center pl-12 pr-4 py-2 text-sm transition-all
                                                    ${isActive
                                                                    ? 'bg-toy-red/10 text-toy-red border-r-4 border-toy-red'
                                                                    : 'text-gray-500 hover:text-gray-300 hover:bg-white/5'
                                                                }
                                                `}
                                                        >
                                                            {/* Vertical guide line */}
                                                            <div className="absolute left-6 top-0 bottom-0 w-px bg-gray-800"></div>
                                                            {isActive && <div className="absolute left-6 top-1/2 -translate-y-1/2 w-1 h-1 rounded-full bg-toy-red -translate-x-1/2 shadow-[0_0_4px_rgba(255,77,77,0.8)]"></div>}

                                                            {sub}
                                                        </button>
                                                    );
                                                })}
                                            </div>
                                        )}
                                    </div>
                                )
                            })}
                    </nav>

                    <div className="p-4 border-t border-gray-800 bg-[#0f172a]">
                        <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-gray-500 uppercase">Mode</span>
                            <ThemeToggle theme={theme} toggleTheme={toggleTheme} />
                        </div>
                    </div>
                </aside>

                {/* Main Content */}
                <main className="flex-1 bg-toy-bg dark:bg-[#121212] overflow-y-auto p-4 lg:p-8 pb-20">

                    {isHomeView ? (
                        <div className="p-4 lg:p-10 max-w-5xl mx-auto animate-[fadeIn_0.5s_ease-out]">
                            <div className="text-center mb-12">
                                <h1 className="text-4xl md:text-6xl font-black mb-4 text-black dark:text-white tracking-tighter">
                                    RED<span className="text-toy-red">TOY</span>
                                </h1>
                                <p className="text-xl md:text-2xl font-bold text-gray-500 dark:text-gray-400">The Playful Red Team Cheatsheet</p>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                {CATEGORY_ORDER.map((key) => {
                                    const def = CATEGORIES[key];
                                    if (!def) return null;
                                    const count = navStructure[key]?.size || 0;

                                    return (
                                        <button
                                            key={key}
                                            onClick={() => {
                                                // Navigate to first available subcategory
                                                const firstSub = Array.from(navStructure[key] || [])[0];
                                                if (firstSub) handleSubnavClick(key, firstSub);
                                            }}
                                            className="bg-white dark:bg-[#1e1e1e] border-4 border-black rounded-xl p-6 shadow-hard hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all text-left group h-full flex flex-col"
                                        >
                                            <div className="flex items-center justify-between mb-4">
                                                <def.icon size={32} className="text-black dark:text-white group-hover:text-toy-red transition-colors" />
                                                <div className="w-8 h-8 bg-black text-white rounded flex items-center justify-center font-black text-sm">
                                                    {count}
                                                </div>
                                            </div>
                                            <h3 className="text-xl font-black uppercase mb-1 text-black dark:text-white group-hover:text-toy-red transition-colors">{def.label}</h3>
                                            <p className="text-xs font-mono text-gray-500 dark:text-gray-400 mt-auto">Explore category &rarr;</p>
                                        </button>
                                    )
                                })}
                            </div>
                        </div>
                    ) : (
                        <>
                            {/* Breadcrumb */}
                            <div className="flex items-center gap-2 text-sm text-gray-500 mb-6 font-mono animate-[fadeIn_0.2s_ease-out]">
                                {isReferenceView ? <BookOpen size={16} /> : isGuideView ? <MapIcon size={16} /> : <TerminalIcon size={16} />}
                                <button onClick={handleLogoClick} className="hover:text-toy-red transition-colors hidden sm:inline">Home</button>
                                <ChevronRight size={14} />
                                <span className="hidden sm:inline">{CATEGORIES[selectedCategory]?.label}</span>
                                <ChevronRight size={14} />
                                <span className="text-toy-red font-bold truncate">{selectedSubcategory}</span>
                            </div>

                            <div className="flex items-end justify-between mb-6 border-b-2 border-black/10 dark:border-white/10 pb-4 animate-[fadeIn_0.2s_ease-out]">
                                <h2 className="text-2xl md:text-3xl font-black uppercase tracking-tight text-black dark:text-white break-words">{selectedSubcategory}</h2>
                            </div>

                            {/* CONTENT SWITCHER: REFERENCE VS GUIDE VS TOOL */}
                            {isReferenceView ? (
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 animate-[fadeIn_0.3s_ease-out]">
                                    {activeReferences.map(ref => (
                                        <a
                                            key={ref.id}
                                            href={ref.url}
                                            target="_blank"
                                            rel="noreferrer"
                                            className="block bg-white dark:bg-[#1e1e1e] border-4 border-black rounded-xl shadow-hard hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all p-6 group"
                                        >
                                            <div className="flex justify-between items-start mb-4">
                                                <div className="p-3 bg-toy-red/10 text-toy-red rounded-lg border-2 border-transparent group-hover:border-toy-red transition-colors">
                                                    <ExternalLink size={24} />
                                                </div>
                                                <span className="text-xs font-black uppercase bg-black text-white px-2 py-1 rounded">LINK</span>
                                            </div>
                                            <h3 className="text-xl font-black text-black dark:text-white mb-2 group-hover:text-toy-red transition-colors">{ref.name}</h3>
                                            <p className="text-sm text-gray-600 dark:text-gray-400 font-medium leading-relaxed">{ref.desc}</p>
                                        </a>
                                    ))}
                                </div>
                            ) : isGuideView ? (
                                <div className="flex flex-col h-full animate-[fadeIn_0.3s_ease-out]">
                                    {/* Guide Tabs */}
                                    <div className="flex flex-wrap gap-2 mb-6">
                                        {/* Deduplicate guides to prevent ghost entries */}
                                        {Array.from(new Map(GUIDES.filter(g => g.category === selectedCategory && g.subcategory === selectedSubcategory).map(g => [g.id, g])).values()).map(guide => (
                                            <button
                                                key={guide.id}
                                                onClick={() => setSelectedToolId(guide.id)}
                                                className={`px-4 py-2 rounded-full border-2 font-black text-xs md:text-sm shadow-hard-sm transition-all
                                        ${selectedToolId === guide.id
                                                        ? 'bg-toy-red text-white border-black translate-y-[2px] shadow-none'
                                                        : 'bg-white text-black border-black hover:-translate-y-1 hover:bg-gray-50'
                                                    }`}
                                            >
                                                {guide.name}
                                            </button>
                                        ))}
                                    </div>

                                    {/* Guide Content */}
                                    {currentGuide && (
                                        <div className="bg-white dark:bg-[#1e1e1e] border-4 border-black rounded-xl shadow-hard p-4 lg:p-10 flex flex-col gap-6">
                                            <div className="flex flex-col gap-2">
                                                <h2 className="text-2xl font-black text-black dark:text-white flex items-center gap-3">
                                                    <span className="w-3 h-8 bg-toy-red rounded-full inline-block"></span>
                                                    {currentGuide.name}
                                                </h2>
                                                <p className="text-gray-600 dark:text-gray-300 font-medium text-lg ml-0 md:ml-6">{currentGuide.desc}</p>
                                            </div>

                                            <div className="w-full border-4 border-black bg-[#0a0a0a] rounded-lg overflow-hidden shadow-hard-sm relative group">
                                                <div className="flex items-center justify-between bg-[#1a1a1a] px-4 py-2 border-b-2 border-white/10">
                                                    <div className="flex gap-2">
                                                        <div className="w-3 h-3 rounded-full bg-toy-red"></div>
                                                        <div className="w-3 h-3 rounded-full bg-yellow-400"></div>
                                                        <div className="w-3 h-3 rounded-full bg-green-400"></div>
                                                    </div>
                                                    <span className="text-xs font-mono text-gray-500 uppercase">guide.sh</span>
                                                </div>
                                                <div className="p-4 lg:p-6 overflow-x-auto">
                                                    <GuideCodeBlock content={currentGuide.content} />
                                                </div>
                                                <div className="absolute top-14 right-4">
                                                    <button
                                                        onClick={() => handleCopy(currentGuide.content)}
                                                        className="bg-white/10 hover:bg-white/20 text-white p-2 rounded border border-white/20 backdrop-blur-sm"
                                                        title="Copy Content"
                                                    >
                                                        <Copy size={16} />
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="flex flex-col h-full animate-[fadeIn_0.3s_ease-out]">
                                    {/* Tool Tabs */}
                                    <div className="flex flex-wrap gap-2 mb-6">
                                        {TOOLS.filter(t => t.category === selectedCategory && t.subcategory === selectedSubcategory).map(tool => (
                                            <button
                                                key={tool.id}
                                                onClick={() => setSelectedToolId(tool.id)}
                                                className={`px-4 py-2 rounded-full border-2 font-black text-xs md:text-sm shadow-hard-sm transition-all
                                        ${selectedToolId === tool.id
                                                        ? 'bg-toy-red text-white border-black translate-y-[2px] shadow-none'
                                                        : 'bg-white text-black border-black hover:-translate-y-1 hover:bg-gray-50'
                                                    }`}
                                            >
                                                {tool.name}
                                            </button>
                                        ))}
                                    </div>

                                    {/* Workspace Panel */}
                                    <div className="bg-white dark:bg-[#1e1e1e] border-4 border-black rounded-xl shadow-hard p-4 lg:p-10 flex flex-col gap-6">

                                        {/* Tool Header */}
                                        <div className="flex flex-col gap-2">
                                            <h2 className="text-2xl font-black text-black dark:text-white flex items-center gap-3">
                                                <span className="w-3 h-8 bg-toy-red rounded-full inline-block"></span>
                                                {currentTool.name}
                                            </h2>
                                            <p className="text-gray-600 dark:text-gray-300 font-medium text-lg ml-0 md:ml-6">{currentTool.desc}</p>
                                        </div>

                                        {/* Configuration Panel */}
                                        {hasConfiguration && (
                                            <div className="bg-gray-50 dark:bg-[#252525] rounded-xl border-2 border-black/10 p-5 flex flex-col gap-4">
                                                <div className="flex items-center gap-2 text-xs font-black uppercase text-gray-400 tracking-widest mb-1">
                                                    <SettingsIcon size={14} /> Configuration
                                                </div>

                                                {/* Render Dynamic Args */}
                                                <div className="flex flex-wrap gap-4 items-end">
                                                    {currentTool.args?.map((arg: ToolArg) => {
                                                        if (arg.type === 'toggle') {
                                                            return (
                                                                <Toggle
                                                                    key={arg.key}
                                                                    label={arg.label}
                                                                    checked={!!toolArgs[arg.key]}
                                                                    onChange={v => updateArg(arg.key, v)}
                                                                />
                                                            );
                                                        }
                                                        if (arg.type === 'text') {
                                                            return (
                                                                <ConfigInput
                                                                    key={arg.key}
                                                                    label={arg.label}
                                                                    value={(toolArgs[arg.key] as string) || ''}
                                                                    onChange={v => updateArg(arg.key, v)}
                                                                    placeholder={arg.placeholder}
                                                                />
                                                            );
                                                        }
                                                        return null;
                                                    })}
                                                </div>
                                            </div>
                                        )}

                                        {/* Command Terminal Area */}
                                        <div className="w-full border-4 border-black bg-[#0a0a0a] rounded-lg overflow-hidden shadow-hard-sm relative group">
                                            {/* Terminal Header */}
                                            <div className="flex items-center justify-between bg-[#1a1a1a] px-4 py-2 border-b-2 border-white/10">
                                                <div className="flex gap-2">
                                                    <div className="w-3 h-3 rounded-full bg-toy-red"></div>
                                                    <div className="w-3 h-3 rounded-full bg-yellow-400"></div>
                                                    <div className="w-3 h-3 rounded-full bg-green-400"></div>
                                                </div>
                                                <span className="text-xs font-mono text-gray-500 uppercase">bash</span>
                                            </div>

                                            {/* Code Display */}
                                            <div className="p-4 lg:p-6 overflow-x-auto">
                                                <pre className="font-mono text-sm md:text-base text-green-400 whitespace-pre-wrap break-all">
                                                    {generatedCommand}
                                                </pre>
                                            </div>

                                            {/* Floating Copy Button */}
                                            <div className="absolute top-14 right-4">
                                                <button
                                                    onClick={() => handleCopy(generatedCommand)}
                                                    className="bg-white/10 hover:bg-white/20 text-white p-2 rounded border border-white/20 backdrop-blur-sm"
                                                    title="Copy Command"
                                                >
                                                    <Copy size={16} />
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </main>
            </div>

            {/* Toast Notification */}
            <div className={`fixed bottom-6 left-1/2 -translate-x-1/2 bg-black text-white px-6 py-3 rounded-full border-2 border-white shadow-[4px_4px_0px_0px_rgba(0,0,0,0.5)] flex items-center gap-3 transition-all duration-300 transform z-50 ${showToast ? 'translate-y-0 opacity-100' : 'translate-y-20 opacity-0'}`}>
                <div className="bg-green-400 rounded-full p-1 text-black">
                    <Check size={16} strokeWidth={4} />
                </div>
                <span className="font-black tracking-wide">COMMAND COPIED!</span>
            </div>

            <GeminiModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
            />
        </div>
    );
};

// Helper component for highlighting guide code comments
const GuideCodeBlock = ({ content }: { content: string }) => {
    return (
        <pre className="font-mono text-sm md:text-base whitespace-pre-wrap break-all">
            {content.split('\n').map((line, i) => {
                // Check if line is a comment
                if (line.trim().startsWith('#')) {
                    return (
                        <span key={i} className="block text-yellow-400 font-bold italic border-l-2 border-yellow-400/50 pl-2 mb-1 mt-2 first:mt-0">
                            {line}
                        </span>
                    );
                }
                // Empty lines
                if (!line.trim()) {
                    return <span key={i} className="block h-4"></span>;
                }
                // Normal code lines
                return (
                    <span key={i} className="block text-green-400 pl-2">
                        {line}
                    </span>
                );
            })}
        </pre>
    );
};

// Sub-components
const Toggle: React.FC<{ label: string, checked: boolean, onChange: (v: boolean) => void }> = ({ label, checked, onChange }) => (
    <div className="flex items-center gap-3 bg-white dark:bg-black/20 px-3 py-2 rounded-lg border-2 border-black/10 dark:border-white/10 select-none cursor-pointer hover:border-black/30 dark:hover:border-white/30 transition-colors h-[42px]" onClick={() => onChange(!checked)}>
        <div className={`relative w-10 h-5 rounded-full p-0.5 transition-colors border-2 border-black ${checked ? 'bg-toy-red' : 'bg-gray-300'}`}>
            <div className={`absolute top-0.5 left-0.5 w-3 h-3 bg-white rounded-full border border-black transition-transform ${checked ? 'translate-x-5' : 'translate-x-0'}`} />
        </div>
        <span className="text-xs font-bold uppercase tracking-wide text-gray-700 dark:text-gray-300">{label}</span>
    </div>
);

const ConfigInput: React.FC<{ label: string, value: string, onChange: (v: string) => void, placeholder?: string }> = ({ label, value, onChange, placeholder }) => (
    <div className="flex flex-col min-w-[150px] flex-1">
        <label className="text-[10px] font-bold uppercase text-gray-500 mb-1">{label}</label>
        <input
            type="text"
            value={value}
            onChange={e => onChange(e.target.value)}
            placeholder={placeholder}
            className="bg-white dark:bg-[#1e1e1e] text-black dark:text-white border-2 border-gray-200 dark:border-gray-600 rounded p-2 text-sm font-mono focus:border-toy-red focus:outline-none transition-colors h-[42px]"
        />
    </div>
);

export default App;
