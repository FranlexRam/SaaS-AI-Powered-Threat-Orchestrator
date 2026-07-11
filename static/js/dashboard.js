// 1. Configuración de la instancia de la gráfica
let attackChart = null;

function initChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    if (attackChart) attackChart.destroy();
    
    attackChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['SQLi', 'RCE', 'XSS', 'DDoS', 'Amenaza Persistente'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#dc2626']
            }]
        }
    });
}

// 2. Función pura de actualización (inyecta al DOM y suma a la gráfica)
function renderEvent(data) {
    const log = document.getElementById('eventLog');
    const isPersistent = data.attack_type.includes("PATRON_PERSISTENTE");
    
    const newEntry = document.createElement('div');
    newEntry.className = `p-2 border-b border-slate-700 ${isPersistent ? 'bg-red-900 animate-bounce' : ''}`;
    newEntry.innerHTML = `
        <div class="flex justify-between">
            <span class="font-bold text-sm">${isPersistent ? '⚠️ CRÍTICO' : data.attack_type}</span>
            <span class="text-xs text-slate-400">${data.risk_level || 'HIGH'}</span>
        </div>
        <div class="text-xs text-slate-400 italic">IP: ${data.source_ip}</div>
    `;
    log.prepend(newEntry);

    // Actualizar gráfica
    const label = isPersistent ? 'Amenaza Persistente' : data.attack_type;
    const index = attackChart.data.labels.indexOf(label);
    if (index !== -1) {
        attackChart.data.datasets[0].data[index]++;
        attackChart.update();
    }
}

// 3. Inicialización Maestra
async function startDashboard() {
    initChart(); // Limpia y crea el lienzo
    
    // A. Cargar todo el historial de la DB
    try {
        const response = await fetch('/api/v1/events', { headers: { 'X-Sakti-API-Key': 'mi_api_key_secreta_123' }});
        const events = await response.json();
        // Cargamos en orden inverso para que los nuevos queden arriba
        events.reverse().forEach(e => renderEvent(e));
    } catch (e) {
        console.warn("No hay historial previo o error de API.");
    }

    // B. Conectar WebSocket solo para eventos futuros
    const ws = new WebSocket("ws://127.0.0.1:8000/ws/security-events/1");
    ws.onmessage = (msg) => renderEvent(JSON.parse(msg.data));
}

document.addEventListener('DOMContentLoaded', startDashboard);