// Aplicación mínima del laboratorio 246: expone un endpoint HTTP en el puerto 8080.
// Solo usa la biblioteca estándar de Go para que el SBOM sea fácil de interpretar.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"
)

// version se puede sobrescribir en el build con -ldflags "-X main.version=..."
var version = "1.0.0"

type respuesta struct {
	App     string `json:"app"`
	Mensaje string `json:"mensaje"`
	Version string `json:"version"`
	Go      string `json:"go"`
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(respuesta{
			App:     "lab246",
			Mensaje: "Laboratorio de seguridad de la cadena de suministro: SBOM y SLSA",
			Version: version,
			Go:      runtime.Version(),
		})
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})

	puerto := os.Getenv("PORT")
	if puerto == "" {
		puerto = "8080"
	}

	srv := &http.Server{
		Addr:              ":" + puerto,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // mitiga ataques tipo Slowloris
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("lab246 %s escuchando en :%s", version, puerto)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
