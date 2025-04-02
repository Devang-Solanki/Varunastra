// Step 2: Create a template for the HTML output
package main

var tmpl = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Scan Report</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			margin: 20px;
		}
		h1 {
			color: #333;
		}
		.table {
			width: 100%;
			border-collapse: collapse;
		}
		.table th, .table td {
			border: 1px solid #ddd;
			padding: 8px;
			text-align: left;
		}
		.table th {
			background-color: #f4f4f4;
		}
		.section {
			margin-bottom: 20px;
		}
	</style>
</head>
<body>
	<h1>Scan Results</h1>
	{{range .}}
		<div class="section">
			<h2>Target: {{.Target}}</h2>
			
			<h3>Secrets Found:</h3>
			{{if .Secrets}}
				<table class="table">
					<tr>
						<th>Issue</th>
						<th>Path</th>
						<th>Type</th>
						<th>Secret</th>
					</tr>
					{{range .Secrets}}
						<tr>
							<td>{{.Issue}}</td>
							<td>{{.Path}}</td>
							<td>{{.Type}}</td>
							<td>{{.Secret}}</td>
						</tr>
					{{end}}
				</table>
			{{else}}
				<p>No secrets found.</p>
			{{end}}

			<h3>Vulnerabilities Found:</h3>
			{{if .Vulnerability}}
				<table class="table">
					<tr>
						<th>Title</th>
						<th>Issue</th>
					</tr>
					{{range .Vulnerability}}
						<tr>
							<td>{{.Title}}</td>
							<td>{{.Issue}}</td>
						</tr>
					{{end}}
				</table>
			{{else}}
				<p>No vulnerabilities found.</p>
			{{end}}

			<h3>Assets:</h3>
			<h4>Domains:</h4>
			{{if .Assets.Domains}}
				<table class="table">
					<tr>
						<th>Domain</th>
						<th>Subdomains</th>
					</tr>
					{{range .Assets.Domains}}
						<tr>
							<td>{{.Domain}}</td>
							<td>{{range .Subdomains}}{{.}} {{end}}</td>
						</tr>
					{{end}}
				</table>
			{{else}}
				<p>No domains found.</p>
			{{end}}

			<h4>URLs:</h4>
			{{if .Assets.Urls}}
				<ul>
					{{range .Assets.Urls}}
						<li>{{.}}</li>
					{{end}}
				</ul>
			{{else}}
				<p>No URLs found.</p>
			{{end}}
		</div>
	{{end}}
</body>
</html>
`
