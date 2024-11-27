// This code runs when the page has finished loading
window.onload = function() {
    // Fetch the data from the PHP script
    fetch('dados.php')
        .then(response => response.json())  // Parse the response as JSON
        .then(data => {
            console.log('Data received:', data);

            // Check if the response contains vulnerabilities data
            if (Object.keys(data).length > 0) {
                // Get the context of the canvas element where the chart will be rendered
                const ctx = document.getElementById('vulnerabilitiesChart').getContext('2d');

                // Labels for the chart (types of vulnerabilities)
                const labels = Object.keys(data);

                // Data for vulnerabilities (number of occurrences)
                const vulnerabilitiesData = Object.values(data);

                // Calculate the total number of vulnerabilities
                const totalVulnerabilities = vulnerabilitiesData.reduce((total, count) => total + count, 0);

                // Display the total number of vulnerabilities in the interface
                document.getElementById('totalVulnerabilities').textContent = `Total Vulnerabilities: ${totalVulnerabilities}`;

                // Chart configuration
                const chart = new Chart(ctx, {
                    type: 'bar',  // Chart type: bar
                    data: {
                        labels: labels,  // Labels for the vulnerabilities (types)
                        datasets: [{
                            label: 'Number of Vulnerabilities',  // Label for the dataset
                            data: vulnerabilitiesData,  // Data for each vulnerability count
                            backgroundColor: 'rgba(54, 162, 235, 0.2)',  // Background color of the bars
                            borderColor: 'rgba(54, 162, 235, 1)',  // Border color of the bars
                            borderWidth: 1  // Border width
                        }]
                    },
                    options: {
                        responsive: true,  // Make the chart responsive to window resizing
                        scales: {
                            y: {
                                beginAtZero: true  // Set the Y-axis to start at zero
                            }
                        }
                    }
                });
            } else {
                // Alert the user if there is an error loading the data
                alert('Error loading data: ' + JSON.stringify(data));
            }
        })
        .catch(error => console.error('Error loading data:', error));  // Handle any errors that occur during data fetching
};
