import React, {useState} from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const Register = () => {
    const [name, setName] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    const navigate = useNavigate();

    const handleSubmit = (e) => {
        e.preventDefault();
        
        try {
            axios.post("http://localhost:8000/register", {
                name: name,
                email: email,
                password: password,
                confirmPassword: confirmPassword
            }).then((res) => {
                console.log(res);
                toast.success("Registration successful.");
                navigate("/login");
            }).catch((error) => {
                console.log(error);
                toast.error("Password does not match.");
            });
        } catch (error) {
            console.log(error);
        }
    }

    return (
        <>
            <ToastContainer />
            <div className="m-10">
                <h1 className="text-2xl font-bold text-gray-900">Daftar Akun</h1>
                <form onSubmit={handleSubmit}>
                    <div className="mt-5">
                        <label htmlFor="name" className="block mb-2 text-sm font-medium text-gray-900">Name</label>
                        <input type="name" name="name" id="name" value={name} onChange={(e) => setName(e.target.value)} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5" placeholder="name@email.com" required />
                    </div>
                    <div className="mt-5">
                        <label htmlFor="email" className="block mb-2 text-sm font-medium text-gray-900">E-Mail</label>
                        <input type="email" name="email" id="email" value={email} onChange={(e) => setEmail(e.target.value)} className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5" placeholder="name@email.com" required />
                    </div>
                    <div className="mt-5">
                        <label htmlFor="password" className="block mb-2 text-sm font-medium text-gray-900">Password</label>
                        <input type="password" name="password" id="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5" required />
                    </div>
                    <div className="mt-5">
                        <label htmlFor="confirmPassword" className="block mb-2 text-sm font-medium text-gray-900">Confirm Password</label>
                        <input type="password" name="confirmPassword" id="confirmPassword" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="••••••••" className="bg-gray-50 border border-gray-300 text-gray-900 sm:text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5" required />
                    </div>
                    <button type="submit" className="w-full my-10 text-black bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center">Register</button>
                    <p className="text-sm font-light text-gray-500">
                        Sudah memiliki akun? <a href="/login" className="font-medium text-primary-600 hover:underline">Masuk</a>
                    </p>
                </form>
            </div>
        </>
    )
}

export default Register;