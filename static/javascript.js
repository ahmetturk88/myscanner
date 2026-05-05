$(document).ready(function() {
    // Initialize DataTable with responsive support
    let table = $('#scans-table').DataTable({
        responsive: true,
        data: [],
        columns: [
            { data: 'id' },
            { 
                data: 'url', 
                render: function(data) {
                    let displayUrl = data.length > 50 ? data.substring(0, 47) + '...' : data;
                    return `<a href="${data}" target="_blank" rel="noopener">${displayUrl}</a>`;
                }
            },
            { 
                data: 'verdict', 
                render: function(data) {
                    if (data === 'Malicious') return '<span class="badge malicious">Malicious</span>';
                    if (data === 'Suspicious') return '<span class="badge suspicious">Suspicious</span>';
                    if (data === 'Safe') return '<span class="badge harmless">Safe</span>';
                    return '<span class="badge unknown">Unknown</span>';
                }
            },
            { 
                data: 'summary', 
                render: function(d) {
                    if (!d) return '-';
                    let clean = d.replace(/https?:\/\/[^\s]+/g, '[URL]');
                    return clean.length > 250 ? clean.substring(0, 247) + '...' : clean;
                }
            },
            { data: 'date' },
            { 
                data: null, 
                render: function(data, type, row) {
                    return `<button class="view-btn" data-id="${row.id}">Show</button>`;
                }
            }
        ],
        pageLength: 5,
        order: [[0, 'desc']],
        language: {
            search: "Search:",
            lengthMenu: "Show _MENU_ entries",
            info: "Showing _START_ to _END_ of _TOTAL_ entries",
            paginate: {
                first: "First",
                last: "Last",
                next: "Next",
                previous: "Previous"
            }
        }
    });

    // Load data from backend
    async function refreshScans() {
        try {
            const res = await fetch('/api/recent_scans');
            if (!res.ok) throw new Error('Fetch failed');
            const data = await res.json();
            table.clear();
            table.rows.add(data.scans);
            table.draw();
        } catch (err) {
            console.error('Error loading scans:', err);
        }
    }

    // Initial load
    refreshScans();

    // Reload button
    $('#load-more-btn').on('click', function() {
        $(this).text('⟳ Loading...');
        refreshScans().then(() => {
            $(this).text('↻ Refresh');
        });
    });

    // Auto refresh every 30 seconds
    setInterval(refreshScans, 30000);

    // Row action - يدعم أيضاً الصفوف الموسعة على الجوال
    $('#scans-table tbody').on('click', '.view-btn', function() {
        const row = table.row($(this).parents('tr')).data();
        if (row && row.url) {
            alert(`Full result for ${row.url}:\n\n${row.summary || 'No summary available'}`);
        }
    });
});