import React, { useEffect } from "react";
import * as wasm from "zebra_wasm";

function App() {
  useEffect(() => {
    wasm.greet();
  }, []);
  return (
    <div>
      <h1>Zebra</h1>
    </div>
  );
}

export default App;
