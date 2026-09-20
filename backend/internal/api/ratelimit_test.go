package api

import (
	"testing"
	"time"
)

func TestSlidingWindowLimiter(t *testing.T) {
	start := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	t.Run("allows up to the limit then blocks", func(t *testing.T) {
		limiter := NewSlidingWindowLimiter(2, time.Minute)
		for i := 0; i < 2; i++ {
			if allowed, _ := limiter.Allow("ip", start); !allowed {
				t.Fatalf("hit %d deveria passar", i+1)
			}
		}
		allowed, retryAfter := limiter.Allow("ip", start)
		if allowed {
			t.Fatal("o terceiro hit deveria ser bloqueado")
		}
		if retryAfter < 1 || retryAfter > 61 {
			t.Fatalf("retryAfter fora da janela: %d", retryAfter)
		}
	})

	t.Run("the window slides", func(t *testing.T) {
		limiter := NewSlidingWindowLimiter(1, time.Minute)
		limiter.Allow("ip", start)
		if allowed, _ := limiter.Allow("ip", start.Add(30*time.Second)); allowed {
			t.Fatal("ainda dentro da janela, deveria bloquear")
		}
		if allowed, _ := limiter.Allow("ip", start.Add(61*time.Second)); !allowed {
			t.Fatal("passada a janela, deveria liberar")
		}
	})

	t.Run("clients are counted apart", func(t *testing.T) {
		limiter := NewSlidingWindowLimiter(1, time.Minute)
		limiter.Allow("ip-a", start)
		if allowed, _ := limiter.Allow("ip-b", start); !allowed {
			t.Fatal("um cliente nao pode gastar a cota do outro")
		}
	})

	t.Run("pruning drops expired windows", func(t *testing.T) {
		limiter := NewSlidingWindowLimiter(5, time.Minute)
		limiter.Allow("ip", start)
		limiter.Prune(start.Add(30 * time.Second))
		if limiter.TrackedKeys() != 1 {
			t.Fatal("janela ainda viva nao deveria ser podada")
		}
		limiter.Prune(start.Add(2 * time.Minute))
		if limiter.TrackedKeys() != 0 {
			t.Fatalf("janela expirada deveria sumir, sobraram %d", limiter.TrackedKeys())
		}
	})
}
