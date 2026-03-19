package validation

import (
	"crypto/x509"
	"fmt"
)

// ChainBuilder строит цепочки сертификатов
type ChainBuilder struct {
	intermediates []*x509.Certificate
}

// NewChainBuilder создает новый построитель цепочек
func NewChainBuilder(intermediates []*x509.Certificate) *ChainBuilder {
	return &ChainBuilder{
		intermediates: intermediates,
	}
}

// BuildPath строит путь от конечного сертификата до доверенного корня
func (cb *ChainBuilder) BuildPath(leaf *x509.Certificate, trustedRoots []*x509.Certificate) ([]*x509.Certificate, error) {
	if leaf == nil {
		return nil, fmt.Errorf("конечный сертификат не может быть nil")
	}

	for _, root := range trustedRoots {
		if leaf.Equal(root) {
			return []*x509.Certificate{leaf}, nil
		}
	}

	visited := make(map[string]bool)
	path, err := cb.buildPathRecursive(leaf, trustedRoots, visited, 0)
	if err != nil {
		fmt.Printf("buildPathRecursive error: %v\n", err)
		return nil, err
	}

	if len(path) > 0 {
		last := path[len(path)-1]
		found := false
		for _, root := range trustedRoots {
			if last.Equal(root) {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("последний сертификат в цепочке не является доверенным корнем")
		}
	}

	return path, nil
}

// / buildPathRecursive рекурсивно строит путь
func (cb *ChainBuilder) buildPathRecursive(
	current *x509.Certificate,
	trustedRoots []*x509.Certificate,
	visited map[string]bool,
	depth int,
) ([]*x509.Certificate, error) {

	if depth > 10 {
		return nil, fmt.Errorf("превышена максимальная глубина цепочки (10)")
	}

	if len(current.SubjectKeyId) > 0 {
		keyID := string(current.SubjectKeyId)
		if visited[keyID] {
			return nil, fmt.Errorf("обнаружен цикл в цепочке сертификатов")
		}
		visited[keyID] = true
	}

	for _, root := range trustedRoots {
		if current.Equal(root) {
			fmt.Printf("Found trusted root at depth %d\n", depth)
			return []*x509.Certificate{current}, nil
		}
	}

	if current.Issuer.String() == current.Subject.String() {
		return nil, fmt.Errorf("найден самоподписанный сертификат, но он не в списке доверенных")
	}

	for _, intermediate := range cb.intermediates {
		if cb.isIssuerOf(intermediate, current) {

			path, err := cb.buildPathRecursive(intermediate, trustedRoots, visited, depth+1)
			if err == nil {
				return append([]*x509.Certificate{current}, path...), nil
			}
			fmt.Printf("Path through issuer %s failed: %v\n", intermediate.Subject.String(), err)
		}
	}

	for _, root := range trustedRoots {
		if cb.isIssuerOf(root, current) {
			return []*x509.Certificate{current, root}, nil
		}
	}

	return nil, fmt.Errorf("не удалось найти издателя для сертификата %s", current.Subject.String())
}

// isIssuerOf проверяет, является ли potentialIssuer издателем cert
func (cb *ChainBuilder) isIssuerOf(potentialIssuer, cert *x509.Certificate) bool {
	if len(cert.AuthorityKeyId) > 0 && len(potentialIssuer.SubjectKeyId) > 0 {
		if string(cert.AuthorityKeyId) != string(potentialIssuer.SubjectKeyId) {
			return false
		}
	}

	if cert.Issuer.String() != potentialIssuer.Subject.String() {
		return false
	}

	if !potentialIssuer.IsCA {
		return false
	}

	return true
}
