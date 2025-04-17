```mermaid
%% Component Diagram for Security Scanner Application - Mermaid Chart Pro Edition
%% Global layout & styling
%%{ init: { 'theme': 'base', 'themeVariables': {
      'primaryColor': '#f96',
      'secondaryColor': '#bbf',
      'tertiaryColor': '#cfc',
      'lineColor': '#333'
    } } }%%
componentDiagram

%% Backend componenten
subgraph Backend
    ScanEngine["Scan Engine"]
    IOCModule["IOC Module"]
    Reporting["Reporting Module"]
end

%% Frontend component
subgraph Frontend
    UI["User Interface"]
end

%% Overige modules
Config["Configuration"]
Network["Network Module"]

%% Relaties tussen de componenten
UI -->|initieert scan| ScanEngine
ScanEngine -->|analyseert inhoud| IOCModule
IOCModule -->|levert indicatoren| Reporting
Config -->|geeft instellingen| ScanEngine
Network -->|haalt externe data op| ScanEngine
Reporting -->|toont resultaten| UI

%% Styling (optioneel, kan aangepast worden)
style ScanEngine fill:#f9f,stroke:#333,stroke-width:2px
style IOCModule fill:#bbf,stroke:#333,stroke-width:2px
style Reporting fill:#cfc,stroke:#333,stroke-width:2px
```