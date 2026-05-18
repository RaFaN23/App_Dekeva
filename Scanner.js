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

        data.headers.forEach(header => {

            html += `
                <p>
                    ${header.header} :
                    <strong>${header.status}</strong>
                </p>
            `
        })

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
                <p>
                    Válido: ${data.ssl.valid}
                </p>
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