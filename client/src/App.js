import { RouterProvider, createBrowserRouter } from 'react-router-dom'

import Login from "./components/Login";
import Register from "./components/Register";
import Dashboard from './components/Dashboard';
import Redirect from './components/Redirect';

const router = createBrowserRouter([
  {
    path: '/login',
    element: <Login/>
  },
  {
    path: '/register',
    element: <Register/>
  },
  {
    path: '/redirect',
    element: <Redirect/>
  },
  {
    path: '/',
    element: <Dashboard/>
  }
]);

function App() {
  return (
    <>
      <RouterProvider router={router}></RouterProvider>
    </>
  );
}

export default App;
