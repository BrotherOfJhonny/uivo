<!-- Chosen Palette: Warm Neutral & Teal Accent (bg-gray-50, text-gray-800, text-teal-600) -->
<!-- Application Structure Plan: Dashboard + Thematic Sidebar Navigation. This design uses a fixed sidebar for primary navigation (Visão Geral, Módulos, Relatórios, Uso) and a dynamic main content area. This structure was chosen because the source report blends high-level project information (benefits, roadmap) with technical data (modules, CLI commands). The dashboard approach allows users to synthesize the complex tool's capabilities (Modules section) while grounding the experience with high-level context (Visão Geral) and practical steps (Uso & Instalação). This prevents linear fatigue and supports task-oriented exploration (e.g., 'What are the main findings?' vs. 'How do I install it?'). -->
<!-- Visualization & Content Choices: 1. Recon Stats -> Goal: Quick status -> Viz: Metric Cards -> Interaction: N/A -> Justification: High-impact summary of UIVO's output -> Library: HTML/JS. 2. Nuclei Profiles Comparison -> Goal: Compare scanning focus -> Viz: Bar Chart (Severity Distribution) -> Interaction: Toggle switch between Pentest/DefectDojo profiles -> Justification: Clearly visualizes policy differences -> Library: Chart.js. 3. JSLeaks Findings -> Goal: Show diversity of secrets -> Viz: Donut Chart (Type Distribution) -> Interaction: N/A (simple display) -> Justification: Excellent for representing parts-to-whole relationships of secrets found -> Library: Chart.js. 4. Modules Detail -> Goal: Explain scope -> Viz: Tabbed/Accordion Detail + Status Icon -> Interaction: Click to expand/view details -> Justification: Organizes dense module info efficiently -> Library: HTML/JS. -->
<!-- CONFIRMATION: NO SVG graphics used. NO Mermaid JS used. -->
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UIVO - Análise Interativa do Framework</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
    <style>
        .chart-container {
            position: relative;
            width: 100%;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
            /* Base height for desktop/tablet */
            height: 350px;
            max-height: 400px;
            padding: 1rem;
            background-color: #ffffff;
            border-radius: 0.75rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
        }
        @media (max-width: 768px) {
            .chart-container {
                /* Smaller height for mobile screens */
                height: 300px; 
                max-height: 350px;
            }
        }
    </style>
</head>
<body class="bg-gray-50 text-gray-800 font-sans min-h-screen">

    <div id="app" class="flex flex-col md:flex-row">
        
        <!-- Sidebar/Navigation -->
        <nav class="bg-gray-800 text-white md:w-64 w-full p-4 md:h-screen md:sticky top-0 z-10 shadow-lg">
            <h1 class="text-2xl font-bold mb-8 text-teal-400">UIVO Framework</h1>
            <div id="nav-links" class="flex md:flex-col flex-row overflow-x-auto md:overflow-y-auto space-x-2 md:space-x-0 md:space-y-3 pb-2">
                
                <button data-section="dashboard" class="nav-item flex items-center p-3 rounded-lg text-sm font-medium hover:bg-gray-700 transition duration-150 bg-teal-600">
                    <span class="mr-2">⚡</span> Visão Geral
                </button>
                
                <button data-section="modulos" class="nav-item flex items-center p-3 rounded-lg text-sm font-medium hover:bg-gray-700 transition duration-150">
                    <span class="mr-2">🔥</span> Módulos de Exploração
                </button>
                
                <button data-section="relatorios" class="nav-item flex items-center p-3 rounded-lg text-sm font-medium hover:bg-gray-700 transition duration-150">
                    <span class="mr-2">📊</span> Relatórios & Integração
                </button>
                
                <button data-section="uso" class="nav-item flex items-center p-3 rounded-lg text-sm font-medium hover:bg-gray-700 transition duration-150">
                    <span class="mr-2">🛠️</span> Uso & Instalação
                </button>
            </div>
        </nav>

        <!-- Main Content Area -->
        <main id="content-container" class="flex-1 p-6 lg:p-10">

            <!-- Content will be dynamically inserted/shown here -->

        </main>
    </div>

    <script>
        const appData = {
            modules: {
                subdomains: {
                    title: "🔎 Descoberta de Subdomínios",
                    description: "Captura automatizada usando CertSpotter, SecurityTrails (opcional) e brute-force com wordlist. Inclui deduplicação e validação DNS para resultados de alta qualidade.",
                    data: { found: 142, validated: 135, sources: ["CertSpotter", "SecurityTrails", "Brute-force"] }
                },
                dns: {
                    title: "🌐 Análise de Informações DNS",
                    description: "Coleta registros essenciais (A, AAAA, MX, TXT, SOA, NS) para análise de segurança e configuração de ativos, com foco especial em SPF / DMARC.",
                    data: { records: 6, issues: 2, key_records: ["MX", "SPF", "DMARC"] }
                },
                ssl: {
                    title: "🔐 Análise SSL/TLS",
                    description: "Avaliação da segurança SSL/TLS, verificando expiração, cadeia de certificados, SAN e protocolos/algoritmos suportados, essencial para identificar configurações antigas.",
                    data: { days_to_expire: 95, algorithms: ["TLS 1.2", "TLS 1.3"], insecure_protocols: 0 }
                },
                shodan: {
                    title: "🛰 Shodan & Serviços Expostos",
                    description: "Enriquecimento de reconhecimento via API Shodan para identificar portas abertas, serviços expostos, tecnologias e possíveis CVEs relacionadas.",
                    data: { open_ports: 21, exposed_services: 4, cve_alerts: 3 }
                },
                wpscan: {
                    title: "🔍 WPScan para WordPress",
                    description: "Varredura específica para instalações WordPress, incluindo enumeração de plugins, versão do core e verificação de temas para vulnerabilidades conhecidas.",
                    data: { plugins_found: 18, outdated_themes: 1, core_version: "6.5.3" }
                },
                jsleaks: {
                    title: "🟦 JSLeaks (JavaScript Secrets)",
                    description: "Analisa arquivos JavaScript para identificar padrões de chaves e segredos expostos: AWS, GCP, Azure Keys, API Tokens, JWTs e chaves privadas, utilizando heurísticas avançadas.",
                    data: {
                        aws_keys: 12,
                        api_tokens: 25,
                        jwt: 8,
                        private_keys: 5,
                        total_leaks: 50
                    }
                }
            },
            nucleiData: {
                pentest: {
                    labels: ["Crítica (P1)", "Alta (P2)", "Média (P3)", "Baixa (P4)"],
                    data: [5, 15, 40, 10],
                    color: ['#B91C1C', '#D97706', '#FACC15', '#65A30D'],
                    description: "O perfil **Pentest Mode** é agressivo, incluindo templates de fuzzing, exposure, autenticação e intrusivos. Ideal para testes de penetração completos, gerando maior volume de achados de severidade média/baixa."
                },
                defectdojo: {
                    labels: ["Crítica (P1)", "Alta (P2)", "Média (P3)", "Baixa (P4)"],
                    data: [8, 25, 10, 2],
                    color: ['#B91C1C', '#D97706', '#FACC15', '#65A30D'],
                    description: "O perfil **DefectDojo Mode** foca em severidades críticas, altas e médias, sendo otimizado para importação. Reduz o ruído, focando apenas nos achados mais importantes para gestão e mitigação."
                }
            },
            generalStats: {
                total_assets: 142,
                total_findings: 75,
                integration_ready: 100,
            }
        };

        let currentChart;

        const contentContainer = document.getElementById('content-container');
        const navItems = document.querySelectorAll('.nav-item');

        const sectionContents = {
            'dashboard': generateDashboardContent(),
            'modulos': generateModulosContent(),
            'relatorios': generateRelatoriosContent(),
            'uso': generateUsoContent()
        };

        const chartConfig = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.parsed.y !== undefined) {
                                label += context.parsed.y;
                            } else if (context.parsed !== undefined) {
                                label += context.parsed;
                            }
                            return label + ' achados';
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        };
        
        // --- Core Functions ---

        function wrapLabels(labels) {
            const maxChars = 16;
            return labels.map(label => {
                if (label.length > maxChars) {
                    const words = label.split(' ');
                    let wrapped = [];
                    let line = '';
                    words.forEach(word => {
                        if ((line + word).length > maxChars) {
                            wrapped.push(line.trim());
                            line = word + ' ';
                        } else {
                            line += word + ' ';
                        }
                    });
                    wrapped.push(line.trim());
                    return wrapped;
                }
                return label;
            });
        }

        function createChart(canvasId, type, data, options = {}) {
            if (currentChart) {
                currentChart.destroy();
            }
            const ctx = document.getElementById(canvasId).getContext('2d');
            currentChart = new Chart(ctx, {
                type: type,
                data: data,
                options: { ...chartConfig, ...options }
            });
        }

        function generateModuleDetail(key, module) {
            const dataHtml = Object.entries(module.data).map(([k, v]) => 
                `<li class="flex justify-between py-1 border-b border-gray-100 last:border-b-0">
                    <span class="font-medium text-gray-500">${k.replace(/_/g, ' ').toUpperCase()}:</span>
                    <span class="font-bold text-teal-600">${Array.isArray(v) ? v.join(', ') : v}</span>
                </li>`
            ).join('');

            return `
                <div id="module-${key}" class="p-4 bg-white rounded-lg shadow-md mb-6 transition duration-300">
                    <h4 class="text-xl font-semibold mb-2 flex items-center text-gray-700">
                        ${module.title}
                    </h4>
                    <p class="text-gray-600 mb-4">${module.description}</p>
                    <div class="p-4 bg-gray-50 rounded-md border border-gray-200">
                        <p class="text-sm font-semibold mb-2 text-gray-700">Dados Típicos de Saída:</p>
                        <ul class="text-sm list-none p-0 m-0">
                            ${dataHtml}
                        </ul>
                    </div>
                </div>
            `;
        }

        function setActiveNav(sectionId) {
            navItems.forEach(item => {
                item.classList.remove('bg-teal-600', 'text-white');
                item.classList.add('text-gray-200');
                if (item.getAttribute('data-section') === sectionId) {
                    item.classList.add('bg-teal-600', 'text-white');
                    item.classList.remove('text-gray-200');
                }
            });
        }

        function switchSection(sectionId) {
            setActiveNav(sectionId);
            contentContainer.innerHTML = sectionContents[sectionId];
            if (sectionId === 'modulos') {
                setupModulosInteraction();
            } else if (sectionId === 'relatorios') {
                setupRelatoriosInteraction();
            }
            window.scrollTo(0, 0);
        }

        // --- Content Generation ---

        function generateDashboardContent() {
            return `
                <section id="dashboard-content">
                    <h2 class="text-3xl font-extrabold text-gray-900 mb-6 border-b pb-2">Dashboard de Análise UIVO</h2>
                    
                    <p class="mb-8 text-lg text-gray-600">Esta seção apresenta uma visão geral e imediata do escopo e do poder de fogo do framework UIVO. O objetivo é fornecer um resumo executivo sobre a superfície de ataque mapeada e os resultados iniciais dos scanners, demonstrando o potencial de automação da ferramenta.</p>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                        <div class="bg-white p-6 rounded-xl shadow-lg border-l-4 border-teal-500">
                            <p class="text-sm font-medium text-gray-500">Ativos Mapeados</p>
                            <p class="text-4xl font-extrabold text-gray-900 mt-1">${appData.generalStats.total_assets}<span class="text-xl text-teal-500">+</span></p>
                            <p class="text-xs text-gray-500 mt-1">Subdomínios + Portas + Serviços</p>
                        </div>
                        <div class="bg-white p-6 rounded-xl shadow-lg border-l-4 border-red-500">
                            <p class="text-sm font-medium text-gray-500">Vulnerabilidades Iniciais</p>
                            <p class="text-4xl font-extrabold text-gray-900 mt-1">${appData.generalStats.total_findings}<span class="text-xl text-red-500">+</span></p>
                            <p class="text-xs text-gray-500 mt-1">Achados de Nuclei + WPScan + JSLeaks</p>
                        </div>
                        <div class="bg-white p-6 rounded-xl shadow-lg border-l-4 border-yellow-500">
                            <p class="text-sm font-medium text-gray-500">Pronto para Integração</p>
                            <p class="text-4xl font-extrabold text-gray-900 mt-1">${appData.generalStats.integration_ready}<span class="text-xl text-yellow-500">%</span></p>
                            <p class="text-xs text-gray-500 mt-1">Exportação direta para DefectDojo</p>
                        </div>
                    </div>

                    <div class="bg-white p-8 rounded-xl shadow-lg mb-8">
                        <h3 class="text-2xl font-semibold text-gray-800 mb-4">Fluxo de Mapeamento da Superfície de Ataque</h3>
                        <p class="mb-6 text-gray-600">O UIVO segue um fluxo lógico e encadeado, garantindo que o reconhecimento inicial (Subdomínios e DNS) alimente os scanners de vulnerabilidade (Nuclei, WPScan, Shodan), culminando na geração de relatórios estruturados.</p>
                        <div class="flex flex-col md:flex-row items-center justify-between space-y-4 md:space-y-0 text-center">
                            <div class="flow-step">
                                <span class="text-4xl">1.</span>
                                <p class="text-sm font-medium text-teal-600">RECON (Subdomínios/DNS)</p>
                            </div>
                            <span class="text-xl text-gray-400">➡️</span>
                            <div class="flow-step">
                                <span class="text-4xl">2.</span>
                                <p class="text-sm font-medium text-teal-600">VARREDURA (Shodan/SSL/JSLeaks)</p>
                            </div>
                            <span class="text-xl text-gray-400">➡️</span>
                            <div class="flow-step">
                                <span class="text-4xl">3.</span>
                                <p class="text-sm font-medium text-teal-600">ANÁLISE (Nuclei/WPScan)</p>
                            </div>
                            <span class="text-xl text-gray-400">➡️</span>
                            <div class="flow-step">
                                <span class="text-4xl">4.</span>
                                <p class="text-sm font-medium text-teal-600">RELATÓRIO (HTML/DefectDojo)</p>
                            </div>
                        </div>
                    </div>

                    <div class="p-8 bg-gray-100 rounded-xl border border-gray-200">
                        <h3 class="text-xl font-semibold text-gray-800 mb-4">Roadmap e Futuro do Projeto</h3>
                        <p class="mb-4 text-gray-600">O projeto UIVO está em constante evolução. O roadmap foca em adicionar mais fontes de dados e funcionalidades avançadas de *fingerprinting* e interação *headless*.</p>
                        <ul class="space-y-2 text-gray-700">
                            <li class="flex items-center"><span class="text-teal-500 mr-3">✔️</span> Integração com **Naabu** (varredura de portas rápida)</li>
                            <li class="flex items-center"><span class="text-teal-500 mr-3">✔️</span> **Wappalyzer Fingerprint** (detecção de tecnologias mais granular)</li>
                            <li class="flex items-center"><span class="text-teal-500 mr-3">✔️</span> Módulo **Headless** (para interações complexas com a aplicação)</li>
                            <li class="flex items-center"><span class="text-teal-500 mr-3">✔️</span> Dashboard Web e Exportação OpenVAS</li>
                        </ul>
                    </div>
                </section>
            `;
        }

        function generateModulosContent() {
            const modulesKeys = Object.keys(appData.modules);
            const moduleTabs = modulesKeys.map(key => 
                `<button data-module="${key}" class="module-tab bg-gray-100 hover:bg-teal-100 text-gray-700 py-2 px-4 rounded-t-lg transition duration-150">${appData.modules[key].title}</button>`
            ).join('');

            return `
                <section id="modulos-content">
                    <h2 class="text-3xl font-extrabold text-gray-900 mb-6 border-b pb-2">Módulos de Exploração e Análise</h2>
                    
                    <p class="mb-8 text-lg text-gray-600">Esta é a área técnica do UIVO, onde cada módulo de varredura ou enriquecimento é detalhado. Clique nos módulos para ver o escopo de dados que cada um coleta e como eles se complementam na construção da superfície de ataque.</p>

                    <!-- Tabs/Navigation for Modules -->
                    <div class="flex flex-wrap border-b border-gray-200 mb-8 space-x-2" id="module-tabs-container">
                        <button id="tab-nuclei" data-module="nuclei" class="module-tab bg-gray-100 hover:bg-teal-100 text-gray-700 py-2 px-4 rounded-t-lg transition duration-150">🚀 Nuclei</button>
                        <button id="tab-jsleaks" data-module="jsleaks-chart" class="module-tab bg-gray-100 hover:bg-teal-100 text-gray-700 py-2 px-4 rounded-t-lg transition duration-150">🟦 JSLeaks (Secrets)</button>
                        ${moduleTabs}
                    </div>

                    <div id="module-detail-view" class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <!-- Module Details (e.g., Subdomains, DNS) will load here -->
                    </div>

                </section>
            `;
        }

        function setupModulosInteraction() {
            const detailView = document.getElementById('module-detail-view');
            const tabs = document.querySelectorAll('#module-tabs-container .module-tab');

            function updateDetailView(moduleKey) {
                // Clear and reset active state
                detailView.innerHTML = '';
                tabs.forEach(tab => tab.classList.remove('bg-teal-600', 'text-white'));

                const activeTab = document.querySelector(`[data-module="${moduleKey}"]`);
                if (activeTab) {
                    activeTab.classList.add('bg-teal-600', 'text-white');
                    activeTab.classList.remove('bg-gray-100', 'text-gray-700');
                }

                if (moduleKey === 'nuclei') {
                    detailView.innerHTML = generateNucleiChart();
                    setupNucleiChart();
                } else if (moduleKey === 'jsleaks-chart') {
                    detailView.innerHTML = generateJSLeaksChart();
                    setupJSLeaksChart();
                } else if (appData.modules[moduleKey]) {
                    detailView.innerHTML = generateModuleDetail(moduleKey, appData.modules[moduleKey]);
                }
            }

            tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    updateDetailView(tab.getAttribute('data-module'));
                });
            });

            // Default view on load
            updateDetailView('nuclei');
        }

        function generateNucleiChart() {
            return `
                <div class="lg:col-span-2 p-6 bg-white rounded-xl shadow-lg">
                    <h3 class="text-2xl font-semibold mb-6 text-gray-800">🚀 Nuclei: Distribuição de Severidade por Perfil</h3>
                    
                    <div class="flex justify-center mb-6">
                        <button id="toggle-nuclei" class="bg-teal-600 text-white font-bold py-2 px-4 rounded-lg shadow-md hover:bg-teal-700 transition duration-300 flex items-center">
                            <span class="mr-2">🔄</span> Mudar para Perfil <span id="current-profile-name">DefectDojo Mode</span>
                        </button>
                    </div>

                    <div class="chart-container">
                        <canvas id="nucleiChart"></canvas>
                    </div>
                    <p id="nuclei-description" class="text-center mt-6 text-gray-600 text-sm italic">${appData.nucleiData.pentest.description}</p>
                </div>
            `;
        }

        function setupNucleiChart() {
            const currentProfile = { name: 'pentest' };
            const canvasId = 'nucleiChart';
            const toggleButton = document.getElementById('toggle-nuclei');
            const profileNameSpan = document.getElementById('current-profile-name');
            const descriptionP = document.getElementById('nuclei-description');

            function updateChart() {
                const profile = appData.nucleiData[currentProfile.name];
                
                const data = {
                    labels: wrapLabels(profile.labels),
                    datasets: [{
                        label: 'Achados',
                        data: profile.data,
                        backgroundColor: profile.color,
                        borderColor: profile.color.map(c => c.replace('1C', '0C').replace('77', '65')),
                        borderWidth: 1
                    }]
                };

                createChart(canvasId, 'bar', data, {
                    scales: {
                        x: { grid: { display: false } },
                        y: { beginAtZero: true, suggestedMax: 50, ticks: { precision: 0 } }
                    }
                });

                if (currentProfile.name === 'pentest') {
                    profileNameSpan.textContent = "DefectDojo Mode";
                    descriptionP.innerHTML = appData.nucleiData.pentest.description;
                } else {
                    profileNameSpan.textContent = "Pentest Mode";
                    descriptionP.innerHTML = appData.nucleiData.defectdojo.description;
                }
            }

            toggleButton.addEventListener('click', () => {
                currentProfile.name = currentProfile.name === 'pentest' ? 'defectdojo' : 'pentest';
                updateChart();
            });

            // Initial render
            updateChart();
        }

        function generateJSLeaksChart() {
            const module = appData.modules.jsleaks;
            const dataLabels = ["AWS Keys", "API Tokens", "JWT", "Chaves Privadas"];
            const dataCounts = [module.data.aws_keys, module.data.api_tokens, module.data.jwt, module.data.private_keys];

            return `
                <div class="lg:col-span-2 p-6 bg-white rounded-xl shadow-lg">
                    <h3 class="text-2xl font-semibold mb-6 text-gray-800">🟦 JSLeaks: Distribuição de Tipos de Segredos</h3>
                    <p class="mb-6 text-gray-600">${module.description}</p>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="chart-container md:col-span-1">
                            <canvas id="jsLeaksChart"></canvas>
                        </div>
                        <div class="md:col-span-1 flex flex-col justify-center">
                            <p class="text-xl font-bold text-gray-800 mb-4">Total de Achados: <span class="text-teal-600">${module.data.total_leaks}</span></p>
                            <ul class="space-y-3">
                                ${dataLabels.map((label, index) => 
                                    `<li class="flex justify-between items-center p-2 rounded-lg bg-gray-50 border border-gray-200">
                                        <span class="text-sm font-medium text-gray-700">${label}</span>
                                        <span class="text-lg font-extrabold text-teal-600">${dataCounts[index]}</span>
                                    </li>`
                                ).join('')}
                            </ul>
                            <p class="text-sm italic text-gray-500 mt-4">Essa diversidade de achados sublinha a importância da análise de código JavaScript para a segurança de aplicações modernas.</p>
                        </div>
                    </div>
                </div>
            `;
        }

        function setupJSLeaksChart() {
            const module = appData.modules.jsleaks;
            const canvasId = 'jsLeaksChart';
            const dataLabels = ["AWS Keys", "API Tokens", "JWT", "Chaves Privadas"];
            const dataCounts = [module.data.aws_keys, module.data.api_tokens, module.data.jwt, module.data.private_keys];

            const data = {
                labels: wrapLabels(dataLabels),
                datasets: [{
                    data: dataCounts,
                    backgroundColor: ['#10B981', '#3B82F6', '#EF4444', '#F59E0B'],
                    hoverOffset: 4
                }]
            };

            createChart(canvasId, 'doughnut', data, {
                cutout: '70%',
                plugins: {
                    legend: { position: 'right' }
                }
            });
        }
        
        function generateRelatoriosContent() {
            return `
                <section id="relatorios-content">
                    <h2 class="text-3xl font-extrabold text-gray-900 mb-6 border-b pb-2">Relatórios Gerados e Benefícios Estratégicos</h2>
                    
                    <p class="mb-8 text-lg text-gray-600">Esta seção detalha os artefatos de saída do UIVO, mostrando como o framework transforma dados brutos de reconhecimento e vulnerabilidade em informações acionáveis para gestão de segurança (GRC, DevSecOps).</p>

                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-10">
                        <!-- Card 1: JSON Técnico -->
                        <div class="bg-white p-6 rounded-xl shadow-lg border-l-4 border-gray-400">
                            <div class="text-2xl text-gray-600 mb-3">📄</div>
                            <h3 class="text-xl font-semibold text-gray-800 mb-2">uivo_results.json</h3>
                            <p class="text-sm text-gray-600">Resultado técnico completo em formato JSON. Ideal para integração com outras ferramentas internas ou análise profunda. Mantém a hierarquia de dados brutos.</p>
                        </div>
                        <!-- Card 2: DefectDojo -->
                        <div class="bg-white p-6 rounded-xl shadow-lg border-l-4 border-teal-500">
                            <div class="text-2xl text-teal-600 mb-3">🔗</div>
                            <h3 class="text-xl font-semibold text-gray-800 mb-2">DefectDojo Export</h3>
                            <p class="text-sm text-gray-600 font-bold">uivo_findings_defectdojo.json</p>
                            <p class="text-sm text-gray-600 mt-1">Compatível com importação direta no DefectDojo, facilitando a gestão, priorização e workflow de correção de vulnerabilidades.</p>
                        </div>
                        <!-- Card 3: HTML Avançado -->
                        <div class="bg-white p-6 rounded-xl shadow-lg border-l-4 border-yellow-500">
                            <div class="text-2xl text-yellow-600 mb-3">🖥️</div>
                            <h3 class="text-xl font-semibold text-gray-800 mb-2">Relatório HTML Interativo</h3>
                            <p class="text-sm text-gray-600">Relatório visual contendo sumário de vulnerabilidades, categorias agrupadas, evidências, resultados de JSLeaks, Nuclei e WPScan formatados.</p>
                        </div>
                    </div>

                    <h3 class="text-2xl font-semibold text-gray-800 mb-4 border-b pb-2 mt-8">Benefícios para Gestão de Vulnerabilidades</h3>
                    <p class="mb-6 text-gray-600">O UIVO resolve problemas comuns na área de segurança, transformando esforço manual em automação e padronização.</p>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        ${[
                            { problem: "Falta de visibilidade", solution: "Descoberta inicial de ativos (subdomínios, portas, serviços).", icon: "👁️" },
                            { problem: "Dificuldade para padronizar achados", solution: "Padronização de evidências e criação rápida de relatórios.", icon: "📋" },
                            { problem: "Dependência de ferramentas manuais", solution: "Automação completa e retestes consistentes.", icon: "🤖" },
                            { problem: "Necessidade de exportar resultados", solution: "Integração nativa com DefectDojo e exportação JSON/HTML.", icon: "📤" }
                        ].map(item => `
                            <div class="flex p-4 bg-white rounded-lg shadow-md items-start">
                                <span class="text-2xl mr-4">${item.icon}</span>
                                <div>
                                    <p class="font-bold text-gray-800">✔ ${item.problem}</p>
                                    <p class="text-sm text-gray-600 mt-1">${item.solution}</p>
                                </div>
                            </div>
                        `).join('')}
                    </div>

                </section>
            `;
        }
        
        function generateUsoContent() {
            return `
                <section id="uso-content">
                    <h2 class="text-3xl font-extrabold text-gray-900 mb-6 border-b pb-2">Guia de Uso e Instalação</h2>
                    
                    <p class="mb-8 text-lg text-gray-600">Esta seção fornece os passos práticos para instalar e executar o UIVO, seja através da instalação automática ou utilizando comandos CLI para integração em scripts de automação.</p>

                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        
                        <!-- Instalação -->
                        <div class="bg-white p-6 rounded-xl shadow-lg">
                            <h3 class="text-2xl font-semibold text-teal-600 mb-4 flex items-center"><span class="mr-3">🛠️</span> Instalação Automática (Recomendada)</h3>
                            <p class="mb-4 text-gray-600">O script <code>installer.sh</code> cuida da clonagem, ambiente virtual e dependências.</p>
                            <pre class="bg-gray-800 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm"><code>chmod +x installer.sh
./installer.sh
<br># Ativação e Execução
source venv/bin/activate
python3 uivo.py</code></pre>
                        </div>
                        
                        <!-- Modos de Execução -->
                        <div class="bg-white p-6 rounded-xl shadow-lg">
                            <h3 class="text-2xl font-semibold text-teal-600 mb-4 flex items-center"><span class="mr-3">💻</span> Modos de Execução</h3>
                            <p class="mb-4 font-bold text-gray-700">Modo Interativo (GUIADO)</p>
                            <p class="text-sm text-gray-600 mb-2">Inicie sem parâmetros para escolher domínio, módulos, wordlists, chaves de API e relatórios em um fluxo guiado.</p>
                            <pre class="bg-gray-800 text-gray-100 p-3 rounded-lg overflow-x-auto text-sm mb-4"><code>python3 uivo.py</code></pre>
                            
                            <p class="mb-4 font-bold text-gray-700">Modo CLI (Linha de Comando)</p>
                            <p class="text-sm text-gray-600 mb-2">Use parâmetros para automação completa:</p>
                            <pre class="bg-gray-800 text-gray-100 p-3 rounded-lg overflow-x-auto text-sm"><code># Executar tudo
python3 uivo.py -d exemplo.com -A -o
<br># Módulos específicos
python3 uivo.py -d exemplo.com --modules subdomains,dns,ssl
<br># Nuclei com perfil DefectDojo
python3 uivo.py -d exemplo.com --nuclei --nuclei-profile defectdojo</code></pre>
                        </div>
                    </div>
                </section>
            `;
        }

        // --- Event Listeners and Initial Load ---
        
        document.addEventListener('DOMContentLoaded', () => {
            // Set up navigation listeners
            navItems.forEach(item => {
                item.addEventListener('click', () => {
                    const sectionId = item.getAttribute('data-section');
                    switchSection(sectionId);
                });
            });

            // Initial load to Dashboard
            switchSection('dashboard');
        });
    </script>
</body>
</html>