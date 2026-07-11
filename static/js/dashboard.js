// Configuración de la Gráfica
const ctx = document.getElementById('attackChart').getContext('2d');
const attackChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['SQLi', 'RCE', 'XSS', 'DDoS', 'Amenaza Persistente'],
        datasets: [{
            data: [0, 0, 0, 0, 0],
            backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#dc2626']
        }]
    }
});

// Conexión WebSocket
const ws = new WebSocket("ws://127.0.0.1:8000/ws/security-events/1");

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    const log = document.getElementById('eventLog');
    const newEntry = document.createElement('div');
    
    // Lógica visual: Si es patrón persistente, le damos un estilo "crítico"
    const isPersistent = data.attack_type.includes("PATRON_PERSISTENTE");
    
    newEntry.className = `border-b py-3 px-2 ${isPersistent ? 'bg-red-900 border-red-500 animate-bounce' : 'border-slate-700'}`;
    newEntry.innerHTML = `
        <div class="flex justify-between">
            <span class="font-bold text-sm">${isPersistent ? '⚠️ ALERTA CRÍTICA' : data.attack_type}</span>
            <span class="text-xs text-slate-400">${data.risk_level}</span>
        </div>
        <div class="text-xs mt-1 italic">IP: ${data.source_ip}</div>
    `;
    
    log.prepend(newEntry);

    // Actualizar la gráfica
    const label = isPersistent ? 'Amenaza Persistente' : data.attack_type;
    const index = attackChart.data.labels.indexOf(label);
    if (index !== -1) {
        attackChart.data.datasets[0].data[index]++;
        attackChart.update();
    }
};