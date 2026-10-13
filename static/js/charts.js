/**
 * BrandShield AI - Dashboard Chart.js Visualizations
 * Dynamic threat distribution and surface exposure analytics.
 */

document.addEventListener('DOMContentLoaded', function () {
  const riskCanvas = document.getElementById('riskDistributionChart');
  const typeCanvas = document.getElementById('scanTypeChart');

  if (!riskCanvas && !typeCanvas) return;

  // Fetch metrics from API or parse injected data
  fetch('/api/dashboard-stats')
    .then(response => response.json())
    .then(data => {
      initCharts(data);
    })
    .catch(err => {
      console.error('Failed to load dashboard statistics:', err);
    });

  function initCharts(data) {
    const categoryCounts = data.category_counts || {};
    const typeCounts = data.type_counts || { "social": 0, "link": 0, "app": 0 };

    const highCount = (categoryCounts['HIGH RISK'] || 0) + (categoryCounts['High'] || 0);
    const suspiciousCount = (categoryCounts['SUSPICIOUS'] || 0) + (categoryCounts['Medium'] || 0);
    const lowCount = (categoryCounts['LOW RISK'] || 0) + (categoryCounts['Low'] || 0);
    const unknownCount = (categoryCounts['UNKNOWN / INSUFFICIENT DATA'] || 0) + (categoryCounts['Unknown'] || 0);

    // 1. Risk Distribution Doughnut Chart
    if (riskCanvas) {
      new Chart(riskCanvas, {
        type: 'doughnut',
        data: {
          labels: ['High Risk', 'Suspicious', 'Low Risk', 'Insufficient Data'],
          datasets: [{
            data: [
              highCount,
              suspiciousCount,
              lowCount,
              unknownCount
            ],
            backgroundColor: [
              '#f43f5e', // High - Rose/Red
              '#fbbf24', // Suspicious - Amber
              '#34d399', // Low - Emerald
              '#64748b'  // Unknown - Slate
            ],
            borderColor: '#111a2f',
            borderWidth: 3,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#94a3b8',
                padding: 16,
                font: {
                  family: "'Plus Jakarta Sans', sans-serif",
                  size: 12,
                  weight: '600'
                },
                usePointStyle: true,
                pointStyle: 'circle'
              }
            },
            tooltip: {
              backgroundColor: '#0c1222',
              borderColor: '#2c4270',
              borderWidth: 1,
              titleColor: '#fff',
              bodyColor: '#94a3b8',
              padding: 12,
              boxPadding: 6,
              cornerRadius: 8
            }
          }
        }
      });
    }

    // 2. Scan Type Breakdown Bar Chart
    if (typeCanvas) {
      new Chart(typeCanvas, {
        type: 'bar',
        data: {
          labels: ['Social Handles', 'Web Links', 'Mobile Apps'],
          datasets: [{
            label: 'Total Analyzed',
            data: [
              typeCounts.social || 0,
              typeCounts.link || 0,
              typeCounts.app || 0
            ],
            backgroundColor: [
              'rgba(56, 189, 248, 0.75)',  // Cyan
              'rgba(168, 85, 247, 0.75)',  // Purple
              'rgba(251, 191, 36, 0.75)'   // Yellow
            ],
            borderColor: [
              '#38bdf8',
              '#a855f7',
              '#fbbf24'
            ],
            borderWidth: 1.5,
            borderRadius: 6,
            barThickness: 34
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            tooltip: {
              backgroundColor: '#0c1222',
              borderColor: '#2c4270',
              borderWidth: 1,
              titleColor: '#fff',
              bodyColor: '#94a3b8',
              padding: 12,
              cornerRadius: 8
            }
          },
          scales: {
            x: {
              grid: {
                display: false
              },
              ticks: {
                color: '#94a3b8',
                font: {
                  size: 11,
                  weight: '600'
                }
              }
            },
            y: {
              beginAtZero: true,
              grid: {
                color: 'rgba(255, 255, 255, 0.05)'
              },
              ticks: {
                stepSize: 1,
                color: '#64748b'
              }
            }
          }
        }
      });
    }
  }
});
