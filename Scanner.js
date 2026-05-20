async function scanWebsite() {

    const url = document.getElementById("urlInput").value
    const results = document.getElementById("results")

    results.innerHTML = "<p>Escaneando...</p>"

    try {

        const response = await fetch(
            `http://127.0.0.1:5000/scan?url=${encodeURIComponent(url)}`
        )

        const data = await response.json()

        if (data.error) {

            results.innerHTML = `
                <div class="result">
                    <h2>Error</h2>
                    <p>${data.error}</p>
                </div>
            `
            return
        }

        let html = `
            <div class="result">
                <h2>${data.url}</h2>
                <p><strong>Status:</strong> ${data.status_code}</p>
                <p><strong>Servidor:</strong> ${data.server}</p>
            </div>
        `

        html += `
            <div class="result">
                <h2>Headers de Seguridad</h2>
        `

        if (data.headers && Array.isArray(data.headers)) {

            data.headers.forEach(header => {

                let solution = ""

                if (header.header === "Content-Security-Policy") {
                    solution = "Añadir una política CSP para bloquear scripts maliciosos."
                }

                else if (header.header === "Strict-Transport-Security") {
                    solution = "Forzar HTTPS usando HSTS."
                }

                else if (header.header === "X-Content-Type-Options") {
                    solution = "Configurar X-Content-Type-Options en nosniff."
                }

                else if (header.header === "X-Frame-Options") {
                    solution = "Configurar X-Frame-Options en DENY o SAMEORIGIN."
                }

                else if (header.header === "Referrer-Policy") {
                    solution = "Limitar información enviada en el encabezado Referer."
                }

                else if (header.header === "Permissions-Policy") {
                    solution = "Restringir permisos sensibles del navegador."
                }

                html += `
                    <div class="result">

                        <p>
                            <strong>${header.header}</strong>
                        </p>

                        <p>
                            Estado:
                            <strong>${header.status}</strong>
                        </p>

                        <p>
                            Mensaje:
                            ${header.message}
                        </p>

                        <p>
                            Solución:
                            ${solution}
                        </p>

                    </div>
                `
            })

        } else {
            html += `<p>No se pudieron obtener headers</p>`
        }

        html += `</div>`

        html += `
            <div class="result">
                <h2>Cookies</h2>
        `

        if (data.cookies.length === 0) {

            html += `<p>No se detectaron cookies</p>`

        } else {

            data.cookies.forEach(cookie => {

                html += `
                    <p>
                        ${cookie.name}
                        | Secure: ${cookie.secure}
                        | HttpOnly: ${cookie.httpOnly}
                    </p>
                `
            })
        }

        html += `</div>`

        html += `
            <div class="result">
                <h2>Formularios</h2>
        `

        if (data.forms.length === 0) {

            html += `<p>No se encontraron formularios</p>`

        } else {

            data.forms.forEach(form => {

                html += `
                    <p>
                        Formulario #${form.form}
                        | CSRF: ${form.csrf}
                    </p>
                `
            })
        }

        html += `</div>`

        html += `
            <div class="result">
                <h2>SSL</h2>
                <p>Válido: ${data.ssl.valid}</p>
            </div>
        `

        results.innerHTML = html

    } catch (error) {

        results.innerHTML = `
            <div class="result">
                <h2>Error</h2>
                <p>${error}</p>
            </div>
        `
    }
}