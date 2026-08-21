package main

import (
	"reflect"
	"testing"
)

// Ce que l'extracteur doit reconnaître dans testdata/aws, et ce qu'il ne doit
// pas inventer.
//
// Le corpus est minuscule et c'est voulu : le vrai fournisseur AWS fait
// plusieurs gigaoctets, et un test qui exigerait de le cloner ne tournerait
// jamais. Ce que ce test protège n'est pas la couverture — c'est que les
// quatre formes que l'extracteur sait lire continuent d'être lues quand
// quelqu'un touche au code.
func TestExtractForceNew(t *testing.T) {
	index, err := extractForceNew("testdata/aws")
	if err != nil {
		t.Fatalf("extraction: %v", err)
	}

	wantTopLevel := []string{"identifier", "restore_to_point_in_time"}
	if got := index.TopLevel["aws_db_instance"]; !reflect.DeepEqual(got, wantTopLevel) {
		t.Errorf("arguments ForceNew de premier niveau = %v, attendu %v", got, wantTopLevel)
	}

	// Un bloc imbriqué porte ses propres ForceNew, et le bloc lui-même en est
	// un. Les deux comptent, et les confondre ferait manquer l'un ou l'autre.
	wantNested := []string{"source_db_instance_identifier"}
	if got := index.Nested["aws_db_instance"]["restore_to_point_in_time"]; !reflect.DeepEqual(got, wantNested) {
		t.Errorf("ForceNew imbriqués = %v, attendu %v", got, wantNested)
	}

	// allocated_storage n'a pas de ForceNew. Le signaler bloquerait une PR
	// pour un changement qui ne détruit rien — le coût d'un faux positif ici
	// est bien plus élevé que celui d'un oubli.
	for _, name := range index.TopLevel["aws_db_instance"] {
		if name == "allocated_storage" {
			t.Error("allocated_storage signalé ForceNew alors qu'il ne l'est pas")
		}
	}

	// Une ressource sans aucun ForceNew est vue et résolue, mais ne contribue
	// rien. C'est ce qui la distingue d'une ressource que l'extracteur n'a pas
	// su lire, et cette distinction est exactement ce que le taux de résolution
	// dans le corps de la PR sert à surveiller.
	if _, present := index.TopLevel["aws_instance"]; present {
		t.Error("aws_instance ne porte aucun ForceNew et ne devrait pas être dans l'index")
	}
	if index.SDKResourcesSeen != 2 {
		t.Errorf("ressources SDKv2 vues = %d, attendu 2", index.SDKResourcesSeen)
	}
	if index.SDKResourcesResolved != 2 {
		t.Errorf("ressources SDKv2 résolues = %d, attendu 2", index.SDKResourcesResolved)
	}
}
