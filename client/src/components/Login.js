import React, { useState, useEffect} from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { useCookies } from "react-cookie";
import { jwtDecode } from "jwt-decode";

import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const Login = () => {
    const [cookie, setCookie] = useCookies(["token"]);

    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");

    const navigate = useNavigate();

    const handleSubmit = (e) => {
        e.preventDefault();
        
        try {
            axios.post("http://localhost:8000/login", {
                email: email,
                password: password,
            }).then((res) => {
                console.log(res);

                toast.success("Login Berhasil.");

                const decoded = jwtDecode(res.data.accessToken);

                setCookie("token", res.data.accessToken, {
                    expires: new Date(Date.now() + decoded.exp),
                });

                navigate("/");
            }).catch((error) => {
                console.log(error);
                toast.error("Email atau Password yang anda masukkan salah.");
            });
        } catch (error) {
            console.log(error);
        }
    }

    return (
        <>
            <ToastContainer />
            <div className="m-10">
                <h1 className="text-2xl font-bold text-gray-900">Login</h1>
                <form onSubmit={handleSubmit}>
                    <div className="mt-5">
                        <label htmlFor="email" className="block mb-2 text-sm font-medium text-gray-900">E-Mail</label>
                        <input type="email" name="email" id="email" value={email} onChange={(e) => setEmail(e.target.value)} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5" placeholder="name@email.com" required />
                    </div>
                    <div className="mt-5">
                        <label htmlFor="password" className="block mb-2 text-sm font-medium text-gray-900">Password</label>
                        <input type="password" name="password" id="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5" required />
                    </div>
                    <button type="submit" className="w-full my-10 text-black bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center">Login</button>
                    <p className="text-sm font-light text-gray-500">
                        Belum memiliki akun? <a href="/register" className="font-medium text-primary-600 hover:underline">Daftar</a>
                    </p>
                </form>
            </div>
        </>
    )
}

export default Login;