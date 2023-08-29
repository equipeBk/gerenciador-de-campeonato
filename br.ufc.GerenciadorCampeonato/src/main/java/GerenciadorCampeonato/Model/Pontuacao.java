package GerenciadorCampeonato.Model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
@Entity
public class Pontuacao {

	@Id
	@GeneratedValue
	private int id;
	private String hora;
	@ManyToOne
	private Partida partida;

	public String getHora() {
		return hora;
	}

	public void setHora(String hora) {
		this.hora = hora;
	}

}
