import React, { Component } from 'react';
import './App.css';
import querystring from 'querystring';
import NodeRSA from 'node-rsa';

const API_HOST = process.env.REACT_APP_API_HOST;

class MessageBox extends React.Component {
  render() {
    const { sendMessage, parentId, elementId, placeholder } = this.props;
    return (<div>
      <textarea ref="message" placeholder={placeholder} id={elementId || 'msgBox'} />
      <button onClick={() => {
        sendMessage(document.getElementById(elementId || 'msgBox').value, parentId);
        this.refs.message.value = '';
      }}>Send</button>
    </div>);
  }
}

class App extends Component {
  constructor() {
    super();
    const localKey = window.localStorage.getItem('privateKey');
    const rsaKey = localKey ? new NodeRSA(localKey) : this.createKey();
    this.state = {
      messages: [],
      currReply: '',
      currBoard: 'default',
      currThread: '',
      rsaKey,
    };
  }
  createKey = () => {
    const rsaKey = new NodeRSA();
    rsaKey.generateKeyPair(1024);
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
    const pubkey = this.state.rsaKey.exportKey('public');
    const sig = this.state.rsaKey.sign(data, 'hex');
    window.fetch(API_HOST + '/send', { method: 'POST', body: JSON.stringify({ data, path, pubkey, sig })});
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
          <h2>You're in channel {this.state.currBoard}</h2>
          <button onClick={() => this.setState({...this.state, rsaKey: this.createKey()})}>Create New ID</button>
          <h3>You're posting as {this.state.rsaKey.exportKey('public')}</h3>
        </div>
        <div style={{ textAlign: 'left', maxHeight: '70vh', overflow: 'scroll' }}>
          {this.state.messages.map(message => {
          //console.log(this.state, message.id)
            // TODO Verify the message signature
            const indentation = message.id.split('/').length * 20;
            return (
            <div style={{ margin: '20px', marginLeft: indentation + 'px', borderRadius: '4px', padding: '4px', boxShadow: '0 3px 6px rgba(0,0,0,0.16), 0 3px 6px rgba(0,0,0,0.23)' }}>
              <pre>{JSON.stringify(message, null, 2)}</pre>
              <div>{message.id}</div>
              <div>{message.id.split('/').pop()}</div>
              <div>{message.data}</div>
              {this.state.currReply === message.id 
              ? <MessageBox sendMessage={this.sendMessage} placeholder="Reply" parentId={this.state.currReply} /> 
              : <button onClick={() => {
                this.setThread(message.id);
                this.setReply(message.id);
                }}>Reply</button>}
            </div>);
            })
          }
        </div>
        <MessageBox sendMessage={this.sendMessage} parentId={`/${this.state.currBoard}`} elementId="newTopic" placeholder="Start a new topic" />
      </div>
    );
  }
}

export default App;
