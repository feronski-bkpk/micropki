package cli

import "strings"

// arrayFlags реализует интерфейс flag.Value для поддержки многократного указания флага
// Используется для флагов типа --san, которые можно указывать несколько раз
type arrayFlags []string

// String возвращает строковое представление массива флагов
func (a *arrayFlags) String() string {
	return strings.Join(*a, ", ")
}

// Set добавляет новое значение к массиву флагов
func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

// Get возвращает массив значений
func (a *arrayFlags) Get() interface{} {
	return []string(*a)
}
