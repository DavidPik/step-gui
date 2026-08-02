package middleware

import "github.com/labstack/echo/v4"

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        // TODO: implement later (FÁZE 6)
        return next(c)
    }
}
