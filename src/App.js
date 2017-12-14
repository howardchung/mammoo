import React, { Component } from 'react';
import logo from './logo.svg';
import './App.css';
import querystring from 'querystring';
import NodeRSA from 'node-rsa';

const API_HOST = 'http://hchung.westus.cloudapp.azure.com:3000';
const MessageBox = ({ sendMessage, parentId, elementId, placeholder }) => (<div>
  <textarea placeholder={placeholder} id={elementId || 'msgBox'} />
  <button onClick={() => {
    sendMessage(document.getElementById(elementId || 'msgBox').value, parentId);
  }}>Send</button>
</div>);

class App extends Component {
  constructor() {
    super();
    const localKey = window.localStorage.getItem('privateKey');
    const rsaKey = localKey ? new NodeRSA(localKey) : this.createKey();
    this.state = {
      messages: [],
      currReply: '',
      currBoard: '',
      currThread: '',
      rsaKey,
    };
  }
  createKey = () => {
    const rsaKey = new NodeRSA();
    rsaKey.generateKeyPair(512);
    window.localStorage.setItem('privateKey', rsaKey.exportKey('private'));
    window.localStorage.setItem('publicKey', rsaKey.exportKey('public'));
    return rsaKey;
  };
  setReply = (messageId) => {
    this.setState({...this.state, currReply: messageId }, () => console.log('asdf', this.state));
  }
  setThread = (threadId) => {
    this.setState({...this.state, currThread: threadId });
  }
  sendMessage = (data, path) => {
    const pubKey = this.state.rsaKey.exportKey('public');
    const sig = this.state.rsaKey.sign(data, 'hex');
    window.fetch(API_HOST + '/send', { method: 'POST', body: JSON.stringify({ data, path, pubKey, sig })});
    this.setState({...this.state, currReply: ''});
    this.receiveMessages();
  }
  receiveMessages = () => {
    window.fetch(API_HOST + '/messages?' + querystring.stringify({ board: this.state.currBoard, thread: this.state.currThread }))
    .then(resp => resp.json())
    .then(json => this.setState({...this.state, messages: json}));
  }
  componentWillMount() {
    this.receiveMessages();
  }
  render() {
    return (
      <div className="App">
        <div className="App-header">
          <img src={logo} className="App-logo" alt="logo" />
          <h2>Welcome to React</h2>
        </div>
        <button onClick={() => this.setState({...this.state, rsaKey: this.createKey()})}>Create New ID</button>
        <p>{this.state.rsaKey.exportKey('public')}</p>
        <MessageBox sendMessage={this.sendMessage} parentId="" elementId="newTopic" placeholder="Start a new topic" />
        <div style={{ textAlign: 'left' }}>
        {this.state.messages.map(message => {
        //console.log(this.state, message.id)
          // TODO Verify the message signature
          const indentation = message.id.split('/').length * 20;
          return (
          <div style={{ marginLeft: indentation + 'px' }}>
            <pre onClick={() => this.setThread(message.id)}>{JSON.stringify(message)}</pre>
            {this.state.currReply === message.id 
            ? <MessageBox sendMessage={this.sendMessage} placeholder="Reply" parentId={this.state.currReply} /> 
            : <button onClick={() => this.setReply(message.id)}>Reply</button>}
          </div>);
          })
        }
        </div>
      </div>
    );
  }
}

export default App;
