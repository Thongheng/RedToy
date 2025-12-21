import { useState, useEffect, useRef, Suspense } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Search } from 'lucide-react';
import type { GlobalInputs } from './types';
import Home from './pages/Home';
import GuidesPage from './pages/Guides';
import ReferencesPage from './pages/References';
import ToolsLayout from './layouts/ToolsLayout';
import { ErrorBoundary } from './components/ErrorBoundary';
import { CommandPalette } from './components/CommandPalette';
import './index.css';

function App() {
    const navigate = useNavigate();
    const location = useLocation();

    // Global State: Inputs (Target, IP, etc.) persisted across app
    // This is OK to be global as it changes rarely compared to tool-specific typing
    const [globalInputs, setGlobalInputs] = useState<GlobalInputs>(() => {
        const saved = localStorage.getItem('redsploit_inputs');
        return saved ? JSON.parse(saved) : { target: '', domain: '', username: '', password: '', filepath: '' };
    });

    const [searchQuery, setSearchQuery] = useState('');

    useEffect(() => {
        localStorage.setItem('redsploit_inputs', JSON.stringify(globalInputs));
    }, [globalInputs]);

    const handleSearch = (value: string) => {
        setSearchQuery(value);
        if (value.trim() && !location.pathname.startsWith('/tools')) {
            navigate('/tools');
        }
    };

    const clearSearch = () => setSearchQuery('');

    return (
        <div className="min-h-screen bg-[#05080d] text-white selection:bg-[#a2ff00] selection:text-black antialiased">
            {/* Grid Background */}
            <div className="fixed inset-0 grid-bg pointer-events-none opacity-[0.08] z-0"></div>

            <div className="relative z-10 flex flex-col min-h-screen">
                {/* Navbar */}
                <nav className="sticky top-0 z-50 bg-[#05080d]/95 backdrop-blur-md border-b border-white/5">
                    <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                        <div className="flex items-center gap-3 cursor-pointer" onClick={() => { navigate('/'); clearSearch(); }}>
                            <div className="w-10 h-10 rounded-lg bg-[#a2ff00]/10 border border-[#a2ff00]/30 flex items-center justify-center">
                                <svg className="w-6 h-6 text-[#a2ff00]" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
                                </svg>
                            </div>
                            <div className="flex items-baseline gap-1.5">
                                <span className="text-xl font-black tracking-tighter">HackToy</span>
                            </div>
                        </div>

                        <div className="flex items-center gap-6">
                            <button
                                onClick={() => navigate('/tools')}
                                className={`font-bold text-sm transition-colors ${location.pathname.startsWith('/tools') ? 'text-[#a2ff00]' : 'text-gray-400 hover:text-white'}`}
                            >
                                Tools
                            </button>
                            <button
                                onClick={() => navigate('/guides')}
                                className={`font-medium text-sm transition-colors ${location.pathname === '/guides' ? 'text-[#a2ff00]' : 'text-gray-400 hover:text-white'}`}
                            >
                                Guides
                            </button>
                            <button
                                onClick={() => navigate('/references')}
                                className={`font-medium text-sm transition-colors ${location.pathname === '/references' ? 'text-[#a2ff00]' : 'text-gray-400 hover:text-white'}`}
                            >
                                References
                            </button>
                        </div>

                        <div className="relative">
                            <input
                                type="text"
                                placeholder="Search tools..."
                                value={searchQuery}
                                onChange={e => handleSearch(e.target.value)}
                                className="bg-[#0d1117] border border-white/10 rounded-lg px-4 py-2 pl-10 text-sm w-64 focus:border-[#a2ff00]/50 focus:outline-none transition-colors"
                            />
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                            {searchQuery && (
                                <button
                                    onClick={clearSearch}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white cursor-pointer"
                                >
                                    ×
                                </button>
                            )}
                        </div>
                    </div>
                </nav>

                {/* Main Content */}
                <main className="flex-1">
                    <ErrorBoundary>
                        <Suspense fallback={<div className="p-10 text-center text-gray-500">Loading components...</div>}>
                            <Routes>
                                <Route path="/" element={<Home />} />
                                <Route path="/guides" element={<GuidesPage />} />
                                <Route path="/references" element={<ReferencesPage />} />

                                {/* Tools Routes */}
                                <Route path="/tools" element={<ToolsLayout globalInputs={globalInputs} searchQuery={searchQuery} clearSearch={clearSearch} />} />
                                <Route path="/tools/:category" element={<ToolsLayout globalInputs={globalInputs} searchQuery={searchQuery} clearSearch={clearSearch} />} />
                                <Route path="/tools/:category/:toolId" element={<ToolsLayout globalInputs={globalInputs} searchQuery={searchQuery} clearSearch={clearSearch} />} />

                                {/* Fallback */}
                                <Route path="*" element={<Navigate to="/" replace />} />
                            </Routes>
                        </Suspense>
                    </ErrorBoundary>
                </main>
            </div>

            <CommandPalette onSelectTool={(toolId, category) => {
                navigate(`/tools/${category}/${toolId}`);
                clearSearch();
            }} />
        </div>
    );
}

export default App;
